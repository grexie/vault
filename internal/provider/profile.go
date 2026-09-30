// Package provider implements declarative, local credential integrations.
// Profiles contain field names and destinations, never credential values or shell scripts.
package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Field struct {
	Name     string `json:"name"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret"`
	Required bool   `json:"required"`
}
type CLI struct {
	Executable string            `json:"executable"`
	Env        map[string]string `json:"env"` // environment variable -> credential field
}
type HTTP struct {
	Origin     string   `json:"origin"`
	PathPrefix string   `json:"pathPrefix"`
	Methods    []string `json:"methods"`
	Auth       Auth     `json:"auth"`
}
type Auth struct {
	Method   string            `json:"method"` // bearer, basic, headers, query
	Token    string            `json:"token,omitempty"`
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"` // header/query name -> credential field
}
type Profile struct {
	Version int     `json:"version"`
	Name    string  `json:"name"`
	Label   string  `json:"label"`
	Fields  []Field `json:"fields"`
	CLI     *CLI    `json:"cli,omitempty"`
	HTTP    *HTTP   `json:"http,omitempty"`
}
type Credentials struct {
	Provider string            `json:"provider"`
	Fields   map[string]string `json:"fields"`
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
var fieldPattern = regexp.MustCompile(`^[a-z][a-zA-Z0-9_]{0,47}$`)
var envPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,79}$`)
var headerPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,79}$`)

func Builtins() map[string]Profile {
	field := func(n, l string, secret, required bool) Field { return Field{n, l, secret, required} }
	return map[string]Profile{
		"login":        {Version: 1, Name: "login", Label: "Website login", Fields: []Field{field("origin", "Website origin", false, true), field("username", "Username", false, true), field("password", "Password", true, true)}},
		"payment-card": {Version: 1, Name: "payment-card", Label: "Payment card", Fields: []Field{field("cardholder", "Cardholder", false, true), field("number", "Card number", true, true), field("expiryMonth", "Expiry month", false, true), field("expiryYear", "Expiry year", false, true)}},
		"github":       {Version: 1, Name: "github", Label: "GitHub", Fields: []Field{field("token", "Access token", true, true), field("host", "Host", false, false)}, CLI: &CLI{Executable: "gh", Env: map[string]string{"GH_TOKEN": "token"}}, HTTP: &HTTP{Origin: "https://api.github.com", PathPrefix: "/", Methods: []string{"GET", "POST", "PATCH", "PUT", "DELETE"}, Auth: Auth{Method: "bearer", Token: "token"}}},
		"aws":          {Version: 1, Name: "aws", Label: "Amazon Web Services", Fields: []Field{field("accessKeyId", "Access key ID", true, true), field("secretAccessKey", "Secret access key", true, true), field("sessionToken", "Session token", true, false), field("region", "Region", false, false)}, CLI: &CLI{Executable: "aws", Env: map[string]string{"AWS_ACCESS_KEY_ID": "accessKeyId", "AWS_SECRET_ACCESS_KEY": "secretAccessKey", "AWS_SESSION_TOKEN": "sessionToken", "AWS_REGION": "region", "AWS_DEFAULT_REGION": "region"}}},
		"cloudflare":   {Version: 1, Name: "cloudflare", Label: "Cloudflare", Fields: []Field{field("token", "API token", true, true), field("accountId", "Account ID", false, false)}, CLI: &CLI{Executable: "wrangler", Env: map[string]string{"CLOUDFLARE_API_TOKEN": "token", "CLOUDFLARE_ACCOUNT_ID": "accountId"}}, HTTP: &HTTP{Origin: "https://api.cloudflare.com", PathPrefix: "/client/v4/", Methods: []string{"GET", "POST", "PUT", "PATCH", "DELETE"}, Auth: Auth{Method: "bearer", Token: "token"}}},
		"docker":       {Version: 1, Name: "docker", Label: "Docker registry", Fields: []Field{field("server", "Registry", false, true), field("username", "Username", false, true), field("password", "Password or access token", true, true)}, CLI: &CLI{Executable: "docker", Env: map[string]string{}}},
	}
}
func Alias(name string) string {
	switch name {
	case "gh":
		return "github"
	case "wrangler":
		return "cloudflare"
	}
	return name
}
func Decode(raw []byte) (Profile, error) {
	var p Profile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 32768 || d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, errors.New("invalid provider JSON")
	}
	return p, p.Validate()
}
func (p Profile) Hash() string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (p Profile) Validate() error {
	bad := errors.New("invalid provider profile")
	if p.Version != 1 || !namePattern.MatchString(p.Name) || strings.TrimSpace(p.Label) == "" || len(p.Label) > 80 || len(p.Fields) == 0 || len(p.Fields) > 32 || p.CLI == nil && p.HTTP == nil && p.Name != "login" && p.Name != "payment-card" {
		return bad
	}
	fields := map[string]bool{}
	for _, f := range p.Fields {
		if !fieldPattern.MatchString(f.Name) || fields[f.Name] || len(f.Label) < 1 || len(f.Label) > 80 {
			return bad
		}
		fields[f.Name] = true
	}
	if p.CLI != nil {
		if !namePattern.MatchString(p.CLI.Executable) || filepath.Base(p.CLI.Executable) != p.CLI.Executable {
			return errors.New("CLI executable must be a program name, without a path or shell arguments")
		}
		for env, field := range p.CLI.Env {
			if !envPattern.MatchString(env) || !fields[field] || unsafeEnv(env) {
				return errors.New("invalid or unsafe CLI environment mapping")
			}
		}
	}
	if p.HTTP != nil {
		h := p.HTTP
		u, e := url.Parse(h.Origin)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("provider HTTP origin must be an explicit HTTPS origin")
		}
		if !strings.HasPrefix(h.PathPrefix, "/") || strings.ContainsAny(h.PathPrefix, "?#\\") || strings.Contains(h.PathPrefix, "..") {
			return errors.New("invalid HTTP path prefix")
		}
		if len(h.Methods) == 0 || len(h.Methods) > 7 {
			return bad
		}
		for _, m := range h.Methods {
			switch m {
			case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
			default:
				return bad
			}
		}
		a := h.Auth
		switch a.Method {
		case "bearer":
			if !fields[a.Token] || a.Username != "" || a.Password != "" || len(a.Fields) != 0 {
				return bad
			}
		case "basic":
			if !fields[a.Username] || !fields[a.Password] || a.Token != "" || len(a.Fields) != 0 {
				return bad
			}
		case "headers", "query":
			if len(a.Fields) == 0 || len(a.Fields) > 8 || a.Token != "" || a.Username != "" || a.Password != "" {
				return bad
			}
			for k, v := range a.Fields {
				if !headerPattern.MatchString(k) || !fields[v] || a.Method == "headers" && unsafeHeader(k) {
					return bad
				}
			}
		default:
			return errors.New("HTTP auth must be bearer, basic, headers or query")
		}
	}
	return nil
}
func unsafeEnv(n string) bool {
	for _, prefix := range []string{"LD_", "DYLD_", "VAULT_", "GIT_CONFIG_", "BASH_FUNC_", "PYTHON", "NODE_"} {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	switch n {
	case "PATH", "HOME", "SHELL", "ENV", "BASH_ENV", "ZDOTDIR", "IFS", "TMPDIR", "XDG_CONFIG_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE":
		return true
	}
	return false
}
func unsafeHeader(n string) bool {
	switch strings.ToLower(n) {
	case "host", "content-length", "connection", "transfer-encoding", "proxy-authorization", "cookie", "set-cookie", "forwarded", "x-forwarded-for", "x-forwarded-host":
		return true
	}
	return false
}
func (p Profile) ValidateCredentials(c Credentials) error {
	if e := p.Validate(); e != nil {
		return e
	}
	if c.Provider != p.Name || len(c.Fields) > len(p.Fields) {
		return errors.New("credentials do not match the provider")
	}
	known := map[string]bool{}
	for _, f := range p.Fields {
		known[f.Name] = true
		v := c.Fields[f.Name]
		if f.Required && v == "" || len(v) > 32768 || strings.ContainsAny(v, "\x00\r\n") {
			return errors.New("missing or invalid credential field: " + f.Name)
		}
	}
	for f := range c.Fields {
		if !known[f] {
			return errors.New("unknown credential field")
		}
	}
	if p.Name == "github" && c.Fields["host"] != "" && c.Fields["host"] != "github.com" {
		return errors.New("GitHub builtin targets github.com; install an explicit profile for your enterprise host")
	}
	if p.Name == "login" {
		u, e := url.Parse(c.Fields["origin"])
		if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return errors.New("login origin must be an exact HTTPS origin")
		}
	}
	if p.Name == "payment-card" {
		number := c.Fields["number"]
		sum := 0
		double := false
		for i := len(number) - 1; i >= 0; i-- {
			n := int(number[i] - '0')
			if n < 0 || n > 9 {
				return errors.New("card number must contain digits only")
			}
			if double {
				n *= 2
				if n > 9 {
					n -= 9
				}
			}
			sum += n
			double = !double
		}
		m, em := strconv.Atoi(c.Fields["expiryMonth"])
		y, ey := strconv.Atoi(c.Fields["expiryYear"])
		if len(number) < 12 || len(number) > 19 || sum%10 != 0 || em != nil || ey != nil || m < 1 || m > 12 || y < 2000 || y > 2200 {
			return errors.New("invalid card number or expiry")
		}
	}
	if p.Name == "docker" {
		s := c.Fields["server"]
		if s != "https://index.docker.io/v1/" {
			u, e := url.Parse("https://" + s)
			if e != nil || u.Host != s || u.User != nil || strings.ContainsAny(s, "/\\?# ") {
				return errors.New("Docker registry must be a hostname with optional port")
			}
		}
	}
	return nil
}
func DecodeCredentials(raw []byte) (Credentials, error) {
	var c Credentials
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 1024*1024 || d.Decode(&c) != nil || d.Decode(new(any)) != io.EOF || !namePattern.MatchString(c.Provider) || len(c.Fields) == 0 || len(c.Fields) > 32 {
		return c, errors.New("invalid credential JSON")
	}
	for k, v := range c.Fields {
		if !fieldPattern.MatchString(k) || len(v) > 32768 || strings.ContainsAny(v, "\x00\r\n") {
			return c, errors.New("invalid credential field")
		}
	}
	if p, ok := Builtins()[c.Provider]; ok {
		return c, p.ValidateCredentials(c)
	}
	return c, nil
}

// Authorize binds a credential to the installed origin, path and method. A
// caller must use a client that rejects redirects, including same-host ones.
func (p Profile) Authorize(r *http.Request, c Credentials) error {
	if e := p.ValidateCredentials(c); e != nil {
		return e
	}
	if p.HTTP == nil {
		return errors.New("profile has no HTTP passthrough")
	}
	h := p.HTTP
	u, _ := url.Parse(h.Origin)
	if r.URL.Scheme != u.Scheme || r.URL.Host != u.Host || r.URL.User != nil || r.URL.Fragment != "" || r.Host != "" && r.Host != u.Host {
		return errors.New("request is outside the provider origin")
	}
	path, e := url.PathUnescape(r.URL.EscapedPath())
	if e != nil || !strings.HasPrefix(path, h.PathPrefix) || strings.ContainsAny(path, "\\\x00\r\n") || strings.Contains(path, "..") {
		return errors.New("request is outside the approved path prefix")
	}
	allowed := false
	for _, m := range h.Methods {
		if m == r.Method {
			allowed = true
		}
	}
	if !allowed {
		return errors.New("method is not allowed by the provider profile")
	}
	r.Header.Del("Authorization")
	r.Header.Del("Proxy-Authorization")
	r.Header.Del("Cookie")
	a := h.Auth
	switch a.Method {
	case "bearer":
		r.Header.Set("Authorization", "Bearer "+c.Fields[a.Token])
	case "basic":
		r.SetBasicAuth(c.Fields[a.Username], c.Fields[a.Password])
	case "headers":
		for k, f := range a.Fields {
			r.Header.Set(k, c.Fields[f])
		}
	case "query":
		q := r.URL.Query()
		for k, f := range a.Fields {
			q.Set(k, c.Fields[f])
		}
		r.URL.RawQuery = q.Encode()
	}
	return nil
}
func (p Profile) FieldNames() []string {
	out := []string{}
	for _, f := range p.Fields {
		out = append(out, f.Name)
	}
	sort.Strings(out)
	return out
}
