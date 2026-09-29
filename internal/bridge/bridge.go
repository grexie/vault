//go:build unix

// Package bridge exposes request-scoped Unix sockets speaking OpenSSH agent
// protocol. It possesses only a revocable capability, never an SSH private key.
package bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/grexie/remote-ssh-agent/internal/access"
	"github.com/grexie/remote-ssh-agent/internal/app"
	"github.com/grexie/remote-ssh-agent/internal/limits"
	"github.com/grexie/remote-ssh-agent/internal/signer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

type Lease struct {
	SigningKey      []byte      `json:"signingKey,omitempty"`
	Request         app.Request `json:"request"`
	Capability      string      `json:"capability"`
	ConnectionToken string      `json:"connectionToken,omitempty"`
	Config          Config      `json:"config"`
}

func RuntimeDir() (string, error) {
	d := filepath.Join(os.TempDir(), fmt.Sprintf("remote-ssh-%d", os.Getuid()))
	// macOS's per-user temp path is long; /tmp has room for Unix socket limits.
	if len(d) > 50 {
		d = fmt.Sprintf("/tmp/remote-ssh-%d", os.Getuid())
	}
	e := os.Mkdir(d, 0700)
	if e != nil && !os.IsExist(e) {
		return "", e
	}
	st, e := os.Lstat(d)
	if e != nil {
		return "", e
	}
	u, ok := st.Sys().(*syscall.Stat_t)
	if !st.IsDir() || st.Mode().Perm() != 0700 || !ok || u.Uid != uint32(os.Getuid()) {
		return "", errors.New("unsafe runtime directory; expected an owned directory with mode 0700")
	}
	return d, nil
}
func paths(c Config, session string) (state, alias, lock string, err error) {
	if !app.SessionPattern.MatchString(session) {
		return "", "", "", errors.New("session must be 1–64 letters, digits, dots, underscores or hyphens")
	}
	d, e := RuntimeDir()
	if e != nil {
		return "", "", "", e
	}
	h := sha256.Sum256([]byte(c.Server + "\x00" + c.Token + "\x00" + session))
	base := filepath.Join(d, hex.EncodeToString(h[:12]))
	return base + ".json", base + ".sock", base + ".lock", nil
}
func Alias(c Config, session string) (string, error) {
	_, alias, _, e := paths(c, session)
	return alias, e
}
func lockSession(path string) (*os.File, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	e = unix.Flock(int(f.Fd()), unix.LOCK_EX)
	if e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func unlock(f *os.File) { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }

func loadLease(c Config, session string) (Lease, string, string, error) {
	state, alias, _, e := paths(c, session)
	if e != nil {
		return Lease{}, "", "", e
	}
	var l Lease
	b, e := os.ReadFile(state)
	if e != nil {
		return l, state, alias, errors.New("no local request for this session")
	}
	if e = json.Unmarshal(b, &l); e != nil {
		return l, state, alias, e
	}
	return l, state, alias, nil
}

// Status returns only public request metadata, never bearer capabilities.
func Status(ctx context.Context, c Config, session string) (app.Request, error) {
	l, _, _, e := loadLease(c, session)
	if e != nil {
		return app.Request{}, e
	}
	var q app.Request
	e = leaseClient(l).Call(ctx, "GET", "/v1/requests/"+l.Request.ID, l.Capability, nil, &q)
	return q, e
}

func Request(ctx context.Context, c Config, session, reason string, duration time.Duration, allowed string, ensure, noWait bool, progress func(string)) (string, error) {
	allowed, e := access.Normalize(allowed)
	if e != nil {
		return "", e
	}
	if duration < time.Second || duration > limits.MaxLeaseDuration {
		return "", errors.New("duration must be between 1s and 48h")
	}
	state, alias, lock, e := paths(c, session)
	if e != nil {
		return "", e
	}
	f, e := lockSession(lock)
	if e != nil {
		return "", e
	}
	defer unlock(f)
	client := New(c)
	if old, _, _, err := loadLease(c, session); err == nil {
		var q app.Request
		e = leaseClient(old).Call(ctx, "GET", "/v1/requests/"+old.Request.ID, old.Capability, nil, &q)
		if e != nil {
			return "", fmt.Errorf("cannot verify the previous request; use revoke to clear it: %w", e)
		}
		if q.Mode == "persistent" {
			return "", errors.New("this session is a persistent grant; use connect or revoke it explicitly")
		}
		if q.Status == "active" || q.Status == "pending" {
			if !ensure {
				return "", errors.New("session already open; use wait, ensure, or revoke")
			}
			oldAccess, _ := access.Normalize(q.Access)
			if q.Reason != reason || q.DurationSeconds != int(duration.Seconds()) || oldAccess != allowed {
				return "", errors.New("existing session has different access, justification, or duration; revoke it first")
			}
			old.Request = q
			if noWait {
				return q.Socket, nil
			}
			return waitAndStart(ctx, old, state, alias, progress)
		}
		_ = os.Remove(state)
		_ = os.Remove(alias)
		_ = os.Remove(q.Socket)
		_ = os.Remove(filepath.Dir(q.Socket))
	}
	d, e := RuntimeDir()
	if e != nil {
		return "", e
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	dir := filepath.Join(d, hex.EncodeToString(b))
	if e = os.Mkdir(dir, 0700); e != nil {
		return "", e
	}
	socket := filepath.Join(dir, "agent.sock")
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return "", e
	}
	var l Lease
	body := map[string]any{"session": session, "reason": reason, "socket": socket, "durationSeconds": int(duration.Seconds()), "requestKey": public}
	if allowed != access.SSH {
		body["access"] = allowed
	}
	e = client.Call(ctx, "POST", "/v1/requests", c.Token, body, &l)
	if e != nil {
		_ = os.Remove(dir)
		return "", e
	}
	l.Config = c
	l.SigningKey = private
	encoded, _ := json.Marshal(l)
	if e = os.WriteFile(state, encoded, 0600); e != nil {
		_ = leaseClient(l).Call(ctx, "POST", "/v1/requests/"+l.Request.ID+"/revoke", l.Capability, map[string]any{}, nil)
		_ = os.Remove(dir)
		return "", e
	}
	if noWait {
		return socket, nil
	}
	return waitAndStart(ctx, l, state, alias, progress)
}

func Wait(ctx context.Context, c Config, session string, progress func(string)) (string, error) {
	_, _, lock, e := paths(c, session)
	if e != nil {
		return "", e
	}
	f, e := lockSession(lock)
	if e != nil {
		return "", e
	}
	defer unlock(f)
	l, state, alias, e := loadLease(c, session)
	if e != nil {
		return "", e
	}
	if l.Request.Mode == "persistent" {
		_, e = waitGrant(ctx, l, progress)
		return "", e
	}
	return waitAndStart(ctx, l, state, alias, progress)
}

func waitAndStart(ctx context.Context, l Lease, state, alias string, progress func(string)) (socket string, err error) {
	client := leaseClient(l)
	ok := false
	defer func() {
		if !ok {
			revokeCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			_ = client.Call(revokeCtx, "POST", "/v1/requests/"+l.Request.ID+"/revoke", l.Capability, map[string]any{}, nil)
			_ = os.Remove(alias)
			_ = os.Remove(l.Request.Socket)
			_ = os.Remove(filepath.Dir(l.Request.Socket))
		}
	}()
	reported := false
	for {
		var q app.Request
		if e := client.Call(ctx, "GET", "/v1/requests/"+l.Request.ID, l.Capability, nil, &q); e != nil {
			return "", e
		}
		l.Request = q
		if q.Status == "active" {
			break
		}
		if q.Status != "pending" {
			return "", fmt.Errorf("request %s: %s", q.Status, q.EndReason)
		}
		if progress != nil && !reported {
			progress("Waiting for phone approval for " + l.Request.Session + "…")
			reported = true
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
	socket = l.Request.Socket
	if conn, e := net.DialTimeout("unix", socket, time.Second); e == nil {
		conn.Close()
		ok = true
		return socket, nil
	}
	// A process can leave a stale Unix socket after a crash. This path is inside
	// our private runtime directory and belongs to this verified request.
	_ = os.Remove(socket)
	exe, e := os.Executable()
	if e != nil {
		return "", e
	}
	cmd := exec.Command(exe, "_bridge")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	in, e := cmd.StdinPipe()
	if e != nil {
		return "", e
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		return "", e
	}
	// The bridge outlives this invocation. Do not retain the caller's stderr
	// pipe: native SSH/SCP (or a captured exec command) must finish when its
	// command exits, rather than waiting for the whole lease to expire.
	// Startup failures are reported by the readiness handshake below.
	cmd.Stderr = nil
	if e = cmd.Start(); e != nil {
		return "", e
	}
	if e = json.NewEncoder(in).Encode(l); e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", e
	}
	_ = in.Close()
	timer := time.AfterFunc(10*time.Second, func() { _ = cmd.Process.Kill() })
	var ready struct {
		OK bool `json:"ok"`
	}
	e = json.NewDecoder(out).Decode(&ready)
	timer.Stop()
	_ = out.Close()
	if e != nil || !ready.OK {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", errors.New("could not start request socket")
	}
	_ = os.Remove(alias)
	if e = os.Symlink(socket, alias); e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", e
	}
	encoded, _ := json.Marshal(l)
	if e = os.WriteFile(state, encoded, 0600); e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "", e
	}
	_ = cmd.Process.Release()
	ok = true
	return socket, nil
}

func Revoke(ctx context.Context, c Config, session string) error {
	state, alias, _, e := paths(c, session)
	if e != nil {
		return e
	}
	client := New(c)
	l, _, _, loadErr := loadLease(c, session)
	if loadErr == nil {
		e = leaseClient(l).Call(ctx, "POST", "/v1/requests/"+l.Request.ID+"/revoke", l.Capability, map[string]any{}, nil)
		// Ordinary capabilities are intentionally discarded on server restart.
		// The paired client can still revoke/clear its own named session. Job
		// configs have no pairing authority and must never take this fallback.
		if e != nil && l.Request.Mode != "connection" {
			e = client.Call(ctx, "POST", "/v1/revoke", c.Token, map[string]string{"session": session}, nil)
		}
	} else {
		e = client.Call(ctx, "POST", "/v1/revoke", c.Token, map[string]string{"session": session}, nil)
	}
	if e != nil {
		return e
	}
	// The worker has been reaped remotely. Remove the alias immediately; the
	// bridge observes terminal status and closes all existing local connections.
	_ = os.Remove(alias)
	l = Lease{}
	if b, e := os.ReadFile(state); e == nil && json.Unmarshal(b, &l) == nil {
		_ = os.Remove(l.Request.Socket)
	}
	_ = os.Remove(state)
	return nil
}

func Run(ctx context.Context, l Lease, ready func() error) error {
	client := leaseClient(l)
	var q app.Request
	if e := client.Call(ctx, "GET", "/v1/requests/"+l.Request.ID, l.Capability, nil, &q); e != nil {
		return e
	}
	if q.Status != "active" {
		return errors.New("grant is not active")
	}
	if q.Socket != l.Request.Socket {
		return errors.New("socket mismatch")
	}
	listener, e := net.Listen("unix", q.Socket)
	if e != nil {
		return e
	}
	if e = os.Chmod(q.Socket, 0600); e != nil {
		listener.Close()
		return e
	}
	ctx, cancel := context.WithDeadline(ctx, q.ExpiresAt)
	defer cancel()
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	defer func() {
		listener.Close()
		mu.Lock()
		for c := range connections {
			c.Close()
		}
		mu.Unlock()
		_ = os.Remove(q.Socket)
		_ = os.Remove(filepath.Dir(q.Socket))
		_, alias, _, _ := paths(l.Config, q.Session)
		if target, e := os.Readlink(alias); e == nil && target == q.Socket {
			_ = os.Remove(alias)
		}
	}()
	if e = ready(); e != nil {
		return e
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				listener.Close()
				return
			case <-t.C:
				var current app.Request
				if err := client.Call(ctx, "GET", "/v1/requests/"+q.ID, l.Capability, nil, &current); err != nil || current.Status != "active" {
					cancel()
					listener.Close()
					return
				}
			}
		}
	}()
	proxy := &remoteAgent{ctx: ctx, client: client, lease: l, cancel: cancel}
	for {
		conn, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		mu.Lock()
		if len(connections) >= 32 {
			mu.Unlock()
			conn.Close()
			continue
		}
		connections[conn] = true
		mu.Unlock()
		go func() {
			defer conn.Close()
			defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
			_ = conn.SetDeadline(q.ExpiresAt)
			_ = agent.ServeAgent(proxy, conn)
		}()
	}
}

type remoteAgent struct {
	ctx    context.Context
	client *Client
	lease  Lease
	cancel context.CancelFunc
}

func (a *remoteAgent) call(m signer.Message) (signer.Reply, error) {
	var r signer.Reply
	e := a.client.Call(a.ctx, "POST", "/v1/requests/"+a.lease.Request.ID+"/agent", a.lease.Capability, m, &r)
	if e != nil {
		a.cancel()
	}
	return r, e
}
func (a *remoteAgent) List() ([]*agent.Key, error) {
	r, e := a.call(signer.Message{Action: "list"})
	if e != nil {
		return nil, e
	}
	key, e := ssh.ParsePublicKey(r.PublicKey)
	if e != nil {
		return nil, e
	}
	return []*agent.Key{{Format: key.Type(), Blob: r.PublicKey, Comment: a.lease.Request.Session}}, nil
}
func (a *remoteAgent) Sign(k ssh.PublicKey, d []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(k, d, 0)
}
func (a *remoteAgent) SignWithFlags(k ssh.PublicKey, d []byte, f agent.SignatureFlags) (*ssh.Signature, error) {
	r, e := a.call(signer.Message{Action: "sign", Key: k.Marshal(), Data: d, Flags: f})
	return r.Signature, e
}

var errReadOnly = errors.New("remote agent is controlled by phone approval and revoke")

func (a *remoteAgent) Add(agent.AddedKey) error       { return errReadOnly }
func (a *remoteAgent) Remove(ssh.PublicKey) error     { return errReadOnly }
func (a *remoteAgent) RemoveAll() error               { return errReadOnly }
func (a *remoteAgent) Lock([]byte) error              { return errReadOnly }
func (a *remoteAgent) Unlock([]byte) error            { return errReadOnly }
func (a *remoteAgent) Signers() ([]ssh.Signer, error) { return nil, errReadOnly }
func (a *remoteAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
