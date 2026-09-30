// Package keychain implements explicit, website-scoped local imports. It never
// enumerates or exports a user's entire keychain, cookies, or browser sessions.
package keychain

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/grexie/vault/internal/provider"
	"golang.org/x/crypto/pbkdf2"
)

type Intent struct {
	Source   string `json:"source"`
	Origin   string `json:"origin"`
	Username string `json:"username"`
	Profile  string `json:"profile"`
}

func (i Intent) Validate() error {
	u, e := url.Parse(i.Origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(i.Username) > 512 || strings.ContainsAny(i.Username, "\x00\r\n") {
		return errors.New("an exact HTTPS origin and valid username are required")
	}
	if i.Source != "chrome" && i.Source != "safari" {
		return errors.New("browser source must be chrome or safari")
	}
	if i.Profile != "" && !regexp.MustCompile(`^(Default|Profile [0-9]{1,4})$`).MatchString(i.Profile) {
		return errors.New("unsupported Chrome profile name")
	}
	return nil
}

type Native interface {
	ChromePassword() ([]byte, error)
	InternetPassword(host, username string) ([]byte, error)
}
type Reader struct {
	mu        sync.Mutex
	native    Native
	chromeKey []byte
}

func NewReader() *Reader { return &Reader{native: newNative()} }
func (r *Reader) Close() { r.mu.Lock(); defer r.mu.Unlock(); clear(r.chromeKey); r.chromeKey = nil }
func (r *Reader) Read(ctx context.Context, in Intent) (provider.Credentials, error) {
	var out provider.Credentials
	if e := in.Validate(); e != nil {
		return out, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if in.Source == "safari" {
		if in.Username == "" {
			return out, errors.New("Safari Keychain import requires --username to select one item")
		}
		u, _ := url.Parse(in.Origin)
		if u.Port() != "" && u.Port() != "443" {
			return out, errors.New("Safari Keychain import supports the standard HTTPS port")
		}
		p, e := r.native.InternetPassword(u.Hostname(), in.Username)
		if e != nil {
			return out, e
		}
		defer clear(p)
		return login(in.Origin, in.Username, p)
	}
	if r.chromeKey == nil {
		password, e := r.native.ChromePassword()
		if e != nil {
			return out, e
		}
		r.chromeKey = pbkdf2.Key(password, []byte("saltysalt"), 1003, 16, sha1.New)
		clear(password)
	}
	return r.readChrome(ctx, in)
}
func login(origin, username string, password []byte) (provider.Credentials, error) {
	c := provider.Credentials{Provider: "login", Fields: map[string]string{"origin": origin, "username": username, "password": string(password)}}
	return c, provider.Builtins()["login"].ValidateCredentials(c)
}
func (r *Reader) readChrome(ctx context.Context, in Intent) (provider.Credentials, error) {
	var out provider.Credentials
	home, e := os.UserHomeDir()
	if e != nil {
		return out, e
	}
	profile := in.Profile
	if profile == "" {
		profile = "Default"
	}
	database := filepath.Join(home, "Library", "Application Support", "Google", "Chrome", profile, "Login Data")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
	// Read-only SQLite query, not a database copy. origin is checked again after
	// parsing. Password blobs remain encrypted until the OS grants key access.
	query := `SELECT origin_url, username_value, hex(password_value) AS encrypted FROM logins WHERE blacklisted_by_user=0 AND (origin_url=` + quote(in.Origin) + ` OR substr(origin_url,1,` + strconv.Itoa(len(in.Origin)+1) + `)=` + quote(in.Origin+"/") + `) LIMIT 101;`
	cmd := exec.CommandContext(ctx, "/usr/bin/sqlite3", "-readonly", "-json", database)
	cmd.Stdin = strings.NewReader(query)
	var b boundedBuffer
	cmd.Stdout = &b
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return out, errors.New("Chrome login storage could not be read; use the browser's password export instead")
	}
	defer clear(b.Bytes())
	var rows []struct {
		Origin    string `json:"origin_url"`
		Username  string `json:"username_value"`
		Encrypted string `json:"encrypted"`
	}
	if json.Unmarshal(b.Bytes(), &rows) != nil {
		return out, errors.New("invalid Chrome login response")
	}
	matches := 0
	var selected []byte
	var username string
	for _, row := range rows {
		u, e := url.Parse(row.Origin)
		if e != nil || u.Scheme+"://"+u.Host != in.Origin || in.Username != "" && row.Username != in.Username {
			continue
		}
		encrypted, e := hex.DecodeString(row.Encrypted)
		if e != nil {
			return out, errors.New("invalid encrypted Chrome password")
		}
		password, e := decryptChrome(r.chromeKey, encrypted)
		clear(encrypted)
		if e != nil {
			clear(selected)
			return out, e
		}
		if selected != nil && bytes.Equal(selected, password) && username == row.Username {
			clear(password)
			continue
		}
		matches++
		clear(selected)
		selected = password
		username = row.Username
	}
	defer clear(selected)
	if matches != 1 {
		return out, errors.New("no unique login matched; specify --username or use a scoped browser export")
	}
	return login(in.Origin, username, selected)
}
func decryptChrome(key, raw []byte) ([]byte, error) {
	bad := errors.New("unsupported or invalid Chrome password encryption; use an official password export")
	if len(raw) < 19 || string(raw[:3]) != "v10" || (len(raw)-3)%16 != 0 {
		return nil, bad
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, bad
	}
	out := append([]byte(nil), raw[3:]...)
	cipher.NewCBCDecrypter(block, bytes.Repeat([]byte{' '}, 16)).CryptBlocks(out, out)
	pad := int(out[len(out)-1])
	if pad < 1 || pad > 16 || pad > len(out) {
		clear(out)
		return nil, bad
	}
	for _, v := range out[len(out)-pad:] {
		if int(v) != pad {
			clear(out)
			return nil, bad
		}
	}
	plain := out[:len(out)-pad]
	if !utf8.Valid(plain) {
		clear(out)
		return nil, bad
	}
	return plain, nil
}
func FromCSV(reader io.Reader, in Intent) (provider.Credentials, error) {
	var out provider.Credentials
	if e := in.Validate(); e != nil {
		return out, e
	}
	raw, e := io.ReadAll(io.LimitReader(reader, 8*1024*1024+1))
	if e != nil || len(raw) > 8*1024*1024 {
		return out, errors.New("password export exceeds 8 MiB")
	}
	defer clear(raw)
	r := csv.NewReader(bytes.NewReader(raw))
	headers, e := r.Read()
	if e != nil {
		return out, errors.New("invalid browser export")
	}
	cols := map[string]int{}
	for n, h := range headers {
		cols[strings.ToLower(strings.TrimPrefix(h, "\ufeff"))] = n
	}
	for _, n := range []string{"url", "username", "password"} {
		if _, ok := cols[n]; !ok {
			return out, errors.New("CSV requires URL, Username and Password columns")
		}
	}
	matches := 0
	for {
		row, e := r.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, errors.New("invalid browser export row")
		}
		u, e := url.Parse(row[cols["url"]])
		if e != nil || u.Scheme+"://"+u.Host != in.Origin || in.Username != "" && row[cols["username"]] != in.Username {
			continue
		}
		if matches > 0 && out.Fields["username"] == row[cols["username"]] && out.Fields["password"] == row[cols["password"]] {
			continue
		}
		matches++
		out, e = login(in.Origin, row[cols["username"]], []byte(row[cols["password"]]))
		if e != nil {
			return out, e
		}
	}
	if matches != 1 {
		return out, errors.New("export contains no unique login for this origin; specify --username")
	}
	return out, nil
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, errors.New("too many matching browser logins")
	}
	return b.Buffer.Write(p)
}
