//go:build unix

package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/grexie/vault/internal/provider"
	"github.com/grexie/vault/internal/vaultwire"
)

func apiVault(ctx context.Context, o vaultOptions, args []string) error {
	if len(args) < 3 {
		return errors.New("usage: vault api PROVIDER METHOD /PATH [--body-stdin]")
	}
	p, e := loadProfile(o, provider.Alias(args[0]))
	if e != nil {
		return e
	}
	if p.HTTP == nil {
		return errors.New("provider has no HTTP profile; use its CLI wrapper")
	}
	method, path := args[1], args[2]
	var body []byte
	if len(args) > 3 {
		if len(args) != 4 || args[3] != "--body-stdin" {
			return errors.New("only --body-stdin is supported after the API path")
		}
		body, e = io.ReadAll(io.LimitReader(os.Stdin, 4*1024*1024+1))
		if e != nil || len(body) > 4*1024*1024 {
			return errors.New("API body exceeds 4 MiB")
		}
		defer clear(body)
	}
	u, e := url.Parse(path)
	if e != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || u.Fragment != "" {
		return errors.New("API path must be relative to the installed provider origin")
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	if o.Agent != "" && o.Agent != c.Config.Device.ID {
		return errors.New("API calls currently run on the requesting user-controlled device")
	}
	payload, _ := json.Marshal(struct {
		vaultwire.Invocation
		Origin   string `json:"origin"`
		Method   string `json:"method"`
		Path     string `json:"path"`
		BodyHash string `json:"bodyHash"`
	}{vaultwire.Invocation{Provider: p.Name, ProfileHash: p.Hash(), Mode: "api"}, p.HTTP.Origin, method, path, vaultwire.Digest(body)})
	q := requestSpec(o, "api", o.Identity, identityType(p), payload)
	q.Network = p.Name
	pending, state, e := waitVault(ctx, c, o, q)
	if e != nil {
		return e
	}
	defer c.CloseRequest(pending.Request.ID)
	grant, e := c.Approval(pending, state)
	if e != nil {
		return e
	}
	defer clear(grant.Secret)
	credentials, e := provider.DecodeCredentials(grant.Secret)
	if e != nil {
		return e
	}
	run, cancel := context.WithDeadline(ctx, grant.ExpiresAt)
	defer cancel()
	go c.Watch(run, pending.Request.ID, cancel)
	r, e := http.NewRequestWithContext(run, method, p.HTTP.Origin+path, bytes.NewReader(body))
	if e != nil {
		return e
	}
	if len(body) > 0 {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "grexie-vault/"+version)
	if e = p.Authorize(r, credentials); e != nil {
		return e
	}
	client := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(r)
	if e != nil {
		return errors.New("provider API request failed")
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		return errors.New("provider redirect refused")
	}
	if _, e = io.Copy(os.Stdout, io.LimitReader(res.Body, 64*1024*1024)); e != nil {
		return e
	}
	if res.StatusCode >= 400 {
		return fmt.Errorf("provider returned HTTP %d", res.StatusCode)
	}
	return nil
}
