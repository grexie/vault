//go:build unix

package bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grexie/vault/internal/app"
	"github.com/grexie/vault/internal/limits"
)

func Grant(ctx context.Context, c Config, session, reason string, idle time.Duration, noWait bool, progress func(string)) (app.Request, error) {
	state, _, lock, e := paths(c, session)
	if e != nil {
		return app.Request{}, e
	}
	f, e := lockSession(lock)
	if e != nil {
		return app.Request{}, e
	}
	defer unlock(f)
	if _, e = os.Lstat(state); !os.IsNotExist(e) {
		return app.Request{}, errors.New("local session already exists; revoke it before creating another grant")
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return app.Request{}, e
	}
	var l Lease
	e = New(c).Call(ctx, "POST", "/v1/requests", c.Token, map[string]any{"session": session, "reason": reason, "mode": "persistent", "access": "ssh", "idleSeconds": int(idle.Seconds()), "requestKey": public}, &l)
	if e != nil {
		return app.Request{}, e
	}
	l.Config = c
	l.SigningKey = private
	b, _ := json.Marshal(l)
	if e = os.WriteFile(state, b, 0600); e != nil {
		revokeLease(l)
		return app.Request{}, e
	}
	if noWait {
		return l.Request, nil
	}
	return waitGrant(ctx, l, progress)
}

func revokeLease(l Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = leaseClient(l).Call(ctx, "POST", "/v1/requests/"+l.Request.ID+"/revoke", l.Capability, map[string]any{}, nil)
}

func waitGrant(ctx context.Context, l Lease, progress func(string)) (q app.Request, err error) {
	defer func() {
		if err != nil && q.LastUsedAt.IsZero() {
			revokeLease(l)
		}
	}()
	if progress != nil {
		progress("Waiting for phone approval of persistent grant " + l.Request.Session + "…")
	}
	for {
		if err = leaseClient(l).Call(ctx, "GET", "/v1/requests/"+l.Request.ID, l.Capability, nil, &q); err != nil {
			return
		}
		if q.Status == "active" {
			return
		}
		if q.Status != "pending" && q.Status != "locked" {
			return q, errors.New("persistent grant " + q.Status)
		}
		select {
		case <-ctx.Done():
			return q, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

type ConnectionToken struct {
	Server  string `json:"server"`
	GrantID string `json:"grantId"`
	Token   string `json:"token"`
}

func ExportGrant(ctx context.Context, c Config, session string) (string, error) {
	l, _, _, e := loadLease(c, session)
	if e != nil {
		return "", e
	}
	q, e := Status(ctx, c, session)
	if e != nil {
		return "", e
	}
	if q.Mode != "persistent" || (q.Status != "active" && q.Status != "locked") || l.ConnectionToken == "" {
		return "", errors.New("approve a persistent grant before exporting its connection token")
	}
	b, _ := json.Marshal(ConnectionToken{Server: c.Server, GrantID: q.ID, Token: l.ConnectionToken})
	return "rsa1." + base64.RawURLEncoding.EncodeToString(b), nil
}

func ParseConnectionToken(value string) (ConnectionToken, error) {
	var t ConnectionToken
	if !strings.HasPrefix(value, "rsa1.") || len(value) > 4096 {
		return t, errors.New("invalid connection token")
	}
	b, e := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "rsa1."))
	if e != nil {
		return t, errors.New("invalid connection token")
	}
	if json.Unmarshal(b, &t) != nil {
		return t, errors.New("invalid connection token")
	}
	if _, e = app.ValidOrigin(t.Server); e != nil {
		return t, e
	}
	secret, e := base64.RawURLEncoding.DecodeString(t.Token)
	if !app.ValidGrantID(t.GrantID) || e != nil || len(secret) != 32 {
		return t, errors.New("invalid connection token")
	}
	return t, nil
}

// Connect needs no pairing token and creates the socket on this machine. Only
// the job capability is persisted locally, never the reusable connection token.
func Connect(ctx context.Context, t ConnectionToken, configPath, session string, duration time.Duration) (string, Config, error) {
	var c Config
	if duration < time.Second || duration > limits.MaxLeaseDuration {
		return "", c, errors.New("connection duration must be 1s–48h")
	}
	if _, e := os.Lstat(configPath); !os.IsNotExist(e) {
		return "", c, errors.New("connect requires a new --config path; refusing to overwrite existing configuration")
	}
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", c, e
	}
	c = Config{Server: t.Server, Token: base64.RawURLEncoding.EncodeToString(b)}
	state, alias, _, e := paths(c, session)
	if e != nil {
		return "", c, e
	}
	d, e := RuntimeDir()
	if e != nil {
		return "", c, e
	}
	dir, e := os.MkdirTemp(d, "job-")
	if e != nil {
		return "", c, e
	}
	socket := filepath.Join(dir, "agent.sock")
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return "", c, e
	}
	var l Lease
	e = New(c).Call(ctx, "POST", "/v1/grants/"+t.GrantID+"/connect", t.Token, map[string]any{"session": session, "socket": socket, "durationSeconds": int(duration.Seconds()), "requestKey": public}, &l)
	if e != nil {
		os.Remove(dir)
		return "", c, e
	}
	l.Config = c
	l.SigningKey = private
	ok := false
	defer func() {
		if !ok {
			revokeLease(l)
			os.Remove(state)
			os.Remove(alias)
			os.Remove(dir)
		}
	}()
	// Exclusive creation prevents clobbering another CLI configuration in a race.
	if e = os.MkdirAll(filepath.Dir(configPath), 0700); e != nil {
		return "", c, e
	}
	f, e := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return "", c, e
	}
	e = json.NewEncoder(f).Encode(c)
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	defer func() {
		if !ok {
			os.Remove(configPath)
		}
	}()
	if e != nil {
		return "", c, e
	}
	encoded, _ := json.Marshal(l)
	if e = os.WriteFile(state, encoded, 0600); e != nil {
		return "", c, e
	}
	socket, e = waitAndStart(ctx, l, state, alias, nil)
	ok = e == nil
	return socket, c, e
}
