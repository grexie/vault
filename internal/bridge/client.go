package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grexie/remote-ssh-agent/internal/app"
)

type Config struct {
	Server string `json:"server"`
	Token  string `json:"token"`
}
type Client struct {
	Config
	HTTP *http.Client
}

func DefaultConfigPath() string {
	if p := os.Getenv("REMOTE_SSH_CONFIG"); p != "" {
		return p
	}
	d, e := os.UserConfigDir()
	if e != nil {
		return "remote-ssh-agent.json"
	}
	return filepath.Join(d, "remote-ssh-agent", "config.json")
}
func Load(path string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, fmt.Errorf("configure this CLI first: %w", e)
	}
	info, e := os.Stat(path)
	if e != nil {
		return c, e
	}
	if info.Mode().Perm()&0077 != 0 {
		return c, errors.New("CLI config must have mode 0600")
	}
	e = json.Unmarshal(b, &c)
	if e != nil {
		return c, e
	}
	_, e = app.ValidOrigin(c.Server)
	if e != nil {
		return c, e
	}
	if c.Token == "" {
		return c, errors.New("missing client token")
	}
	return c, nil
}
func Save(path string, c Config) error {
	if _, e := app.ValidOrigin(c.Server); e != nil {
		return e
	}
	if len(c.Token) < 32 {
		return errors.New("invalid client token")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, b, 0600)
}
func New(c Config) *Client {
	return &Client{Config: c, HTTP: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not permitted") }}}
}
func (c *Client) Call(ctx context.Context, method, path, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return e
		}
		body = bytes.NewReader(b)
	}
	r, e := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(c.Server, "/")+path, body)
	if e != nil {
		return e
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	res, e := c.HTTP.Do(r)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if e != nil {
		return e
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var v struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(b, &v)
		if v.Error == "" {
			v.Error = res.Status
		}
		return errors.New(v.Error)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}
