//go:build unix

package command

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"
	"github.com/grexie/vault/internal/ageio"
	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/deviceagent"
	"github.com/grexie/vault/internal/vaultwire"
)

var managedSession = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

type savedSession struct {
	Config   string         `json:"config"`
	Endpoint string         `json:"endpoint"`
	Pending  device.Pending `json:"pending"`
}

func managedSettings(o *vaultOptions, c *device.Client) {
	if o.Agent == "" {
		o.Agent = c.Config.AgentID
	}
	if o.Agent == "" {
		o.Agent = c.Config.Device.ID
	}
	if o.AgentURL == "" {
		o.AgentURL = c.Config.AgentURL
	}
	if o.AgentURL == "" {
		o.AgentURL = "http://127.0.0.1:8792"
	}
}
func managedFile(o vaultOptions) (string, error) {
	if !managedSession.MatchString(o.Session) {
		return "", errors.New("a session name using letters, digits, dots, hyphens or underscores is required")
	}
	return filepath.Join(filepath.Dir(o.Config), "sessions", o.Session+".json"), nil
}
func readManaged(o vaultOptions) (savedSession, error) {
	var s savedSession
	file, e := managedFile(o)
	if e != nil {
		return s, e
	}
	b, e := cloudstore.ReadSecret(file, 1024*1024)
	if e != nil {
		return s, errors.New("session not found")
	}
	e = json.Unmarshal(b, &s)
	if e == nil && (s.Config != o.Config || s.Pending.Request.Session != o.Session) {
		e = errors.New("invalid saved session")
	}
	return s, e
}
func managedSocket(s savedSession) (string, error) {
	dir := fmt.Sprintf("/tmp/grexie-vault-%d", os.Getuid())
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return "", e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return "", e
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !st.IsDir() || st.Mode().Perm() != 0700 {
		return "", errors.New("unsafe socket directory")
	}
	return filepath.Join(dir, "ssh-"+vaultwire.Digest([]byte(s.Config + ":" + s.Pending.Request.ID))[:24]+".sock"), nil
}
func managedCommand(ctx context.Context, o vaultOptions, cmd string, args []string) error {
	if cmd == "agent" {
		return agentVault(ctx, o, args)
	}
	if cmd == "_device-bridge" {
		if len(args) != 1 {
			return errors.New("internal bridge requires session file")
		}
		b, e := cloudstore.ReadSecret(args[0], 1024*1024)
		if e != nil {
			return e
		}
		var s savedSession
		if json.Unmarshal(b, &s) != nil {
			return errors.New("invalid session")
		}
		return serveManagedBridge(ctx, s)
	}
	if cmd == "encrypt" || cmd == "decrypt" {
		return managedCrypt(ctx, o, cmd, args)
	}
	if cmd == "ssh" || cmd == "scp" {
		return managedSSH(ctx, o, cmd, args)
	}
	f := flags(cmd)
	f.StringVar(&o.Session, "session", o.Session, "unique session name")
	f.StringVar(&o.Reason, "reason", o.Reason, "request justification")
	f.StringVar(&o.Identity, "identity", o.Identity, "SSH identity name")
	f.StringVar(&o.Agent, "agent", o.Agent, "paired signing device ID")
	f.StringVar(&o.AgentURL, "agent-url", o.AgentURL, "signing device HTTPS origin")
	f.DurationVar(&o.Duration, "duration", o.Duration, "approval duration, maximum 48h")
	f.DurationVar(&o.Timeout, "timeout", o.Timeout, "approval wait timeout")
	noWait := f.Bool("no-wait", false, "submit without waiting")
	access := f.String("access", "ssh", "ssh or age")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	managedSettings(&o, c)
	file, e := managedFile(o)
	if e != nil {
		return e
	}
	switch cmd {
	case "request":
		if len(strings.TrimSpace(o.Reason)) < 8 || o.Duration < time.Second || o.Duration > 48*time.Hour || (*access != "ssh" && *access != "age") {
			return errors.New("supply a justification, ssh/age access and a duration from 1s to 48h")
		}
		if device.ValidateServer(o.AgentURL) != nil {
			return errors.New("agent endpoint must use HTTPS or literal loopback")
		}
		if old, e := readManaged(o); e == nil {
			state, e := c.Status(ctx, old.Pending.Request.ID)
			if e == nil && (state.Status == "pending" || state.Status == "approved") {
				return errors.New("session already exists; use wait or revoke")
			}
		}
		q := requestSpec(o, *access, o.Identity, "ssh", nil)
		q.Managed = true
		q.AgentID = o.Agent
		p, e := c.Submit(ctx, q)
		if e != nil {
			return e
		}
		s := savedSession{o.Config, o.AgentURL, p}
		raw, _ := json.Marshal(s)
		if e = device.SavePrivate(file, raw); e != nil {
			c.CloseRequest(p.Request.ID)
			return e
		}
		if *noWait {
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": p.Request.ID, "session": p.Request.Session, "status": "pending"})
		}
		return waitManaged(ctx, o, c, s)
	case "wait":
		s, e := readManaged(o)
		if e != nil {
			return e
		}
		return waitManaged(ctx, o, c, s)
	case "status":
		s, e := readManaged(o)
		if e != nil {
			return e
		}
		state, e := c.Status(ctx, s.Pending.Request.ID)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": state.ID, "session": state.Session, "status": state.Status, "expiresAt": state.ExpiresAt})
	case "revoke":
		s, e := readManaged(o)
		if e != nil {
			return e
		}
		if e = c.Revoke(ctx, s.Pending.Request.ID); e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Session revoked:", o.Session)
		return nil
	}
	return errors.New("unknown managed command")
}
func waitManaged(ctx context.Context, o vaultOptions, c *device.Client, s savedSession) error {
	if o.Timeout < time.Second || o.Timeout > 15*time.Minute {
		return errors.New("approval timeout must be 1s to 15m")
	}
	wait, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	state, e := c.Wait(wait, s.Pending, os.Stderr)
	if e != nil {
		return e
	}
	for {
		_, e = c.RPC(wait, s.Endpoint, s.Pending, state, "ping", nil)
		if !errors.Is(e, device.ErrPending) {
			break
		}
		select {
		case <-wait.Done():
			return wait.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if e != nil {
		return e
	}
	if s.Pending.Request.Kind == "age" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"session": s.Pending.Request.Session, "status": "approved", "expiresAt": state.ExpiresAt})
	}
	socket, e := managedSocket(s)
	if e != nil {
		return e
	}
	if conn, e := net.DialTimeout("unix", socket, time.Second); e == nil {
		conn.Close()
		fmt.Fprintln(os.Stdout, socket)
		return nil
	}
	if _, e = os.Lstat(socket); e == nil {
		return errors.New("stale socket exists; remove it after confirming no bridge is running")
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	file, e := managedFile(o)
	if e != nil {
		return e
	}
	command := exec.Command(exe, "--config", s.Config, "_device-bridge", file)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e = command.Start(); e != nil {
		return e
	}
	command.Process.Release()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, e := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			fmt.Fprintln(os.Stdout, socket)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("client-local SSH bridge did not start")
}
func serveManagedBridge(ctx context.Context, s savedSession) error {
	cfg, e := device.Load(s.Config)
	if e != nil {
		return e
	}
	c := device.New(cfg)
	state, e := c.Status(ctx, s.Pending.Request.ID)
	if e != nil {
		return e
	}
	auth, _, e := c.Authorization(s.Pending, state)
	if e != nil {
		return e
	}
	scope, cancel := context.WithDeadline(ctx, auth.ExpiresAt)
	defer cancel()
	socket, e := managedSocket(s)
	if e != nil {
		return e
	}
	listener, e := net.Listen("unix", socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(socket)
	if e = os.Chmod(socket, 0600); e != nil {
		return e
	}
	go func() { <-scope.Done(); listener.Close() }()
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-scope.Done():
				return
			case <-tick.C:
				if _, e := c.RPC(scope, s.Endpoint, s.Pending, state, "ping", nil); e != nil {
					cancel()
					return
				}
			}
		}
	}()
	for {
		conn, e := listener.Accept()
		if e != nil {
			if scope.Err() != nil {
				return nil
			}
			return e
		}
		go func() {
			serveManagedSSHConn(scope, conn, func(message []byte) ([]byte, error) {
				return c.RPC(scope, s.Endpoint, s.Pending, state, "ssh", message)
			})
		}()
	}
}

func serveManagedSSHConn(ctx context.Context, conn net.Conn, rpc func([]byte) ([]byte, error)) {
	defer conn.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-finished:
		}
	}()
	for {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		header := make([]byte, 4)
		if _, e := io.ReadFull(conn, header); e != nil {
			return
		}
		n := binary.BigEndian.Uint32(header)
		if n < 1 || n > 262140 {
			return
		}
		message := make([]byte, 4+int(n))
		copy(message, header)
		if _, e := io.ReadFull(conn, message[4:]); e != nil {
			return
		}
		// OpenSSH probes session-bind@openssh.com before listing keys. Refuse
		// unsupported extensions and all mutations with SSH_AGENT_FAILURE,
		// preserving the connection so the client can list/sign afterwards.
		// Only list (11) and sign (13) ever reach the signing device.
		reply := []byte{0, 0, 0, 1, 5}
		if message[4] == 11 || message[4] == 13 {
			var e error
			reply, e = rpc(message)
			if e != nil {
				return
			}
		}
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, e := conn.Write(reply); e != nil {
			return
		}
	}
}

func agentVault(ctx context.Context, o vaultOptions, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vault agent serve|configure|info")
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	switch args[0] {
	case "info":
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"id": c.Config.Device.ID, "name": c.Config.Device.Name, "defaultAgent": c.Config.AgentID, "agentURL": c.Config.AgentURL})
	case "configure":
		f := flags("agent configure")
		id := f.String("id", c.Config.Device.ID, "paired signing device ID")
		endpoint := f.String("url", "http://127.0.0.1:8792", "signing device HTTPS origin")
		if e = f.Parse(args[1:]); e != nil {
			return e
		}
		if e = device.ValidateServer(*endpoint); e != nil {
			return e
		}
		c.Config.AgentID = *id
		c.Config.AgentURL = *endpoint
		return device.Save(o.Config, c.Config)
	case "serve":
		if c.Config.Device.Role != "agent" {
			return errors.New("pair a dedicated signing-agent configuration with vault pair --role agent first")
		}
		f := flags("agent serve")
		listen := f.String("listen", "127.0.0.1:8792", "loopback listener behind device-controlled HTTPS/Tailscale")
		if e = f.Parse(args[1:]); e != nil {
			return e
		}
		host, _, e := net.SplitHostPort(*listen)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("agent must listen on literal loopback; expose through device-controlled HTTPS")
		}
		a := deviceagent.New(c)
		defer a.Close()
		go a.Run(ctx)
		server := &http.Server{Addr: *listen, Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second}
		go func() { <-ctx.Done(); server.Close() }()
		fmt.Fprintln(os.Stderr, "Signing device ready. No SSH socket is created on this device.")
		e = server.ListenAndServe()
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
	return errors.New("unknown agent command")
}
func managedSSH(ctx context.Context, o vaultOptions, cmd string, args []string) error {
	if len(args) == 0 {
		return errors.New("supply native SSH/SCP arguments")
	}
	if len(strings.TrimSpace(o.Reason)) < 8 {
		return errors.New("supply --reason before ssh/scp")
	}
	if o.Session == "" {
		o.Session = "ssh-" + device.RandomID()[:16]
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	managedSettings(&o, c)
	q := requestSpec(o, "ssh", o.Identity, "ssh", nil)
	q.Managed = true
	q.AgentID = o.Agent
	p, state, e := waitVault(ctx, c, o, q)
	if e != nil {
		return e
	}
	defer c.CloseRequest(p.Request.ID)
	s := savedSession{o.Config, o.AgentURL, p}
	file, e := managedFile(o)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(s)
	if e = device.SavePrivate(file, b); e != nil {
		return e
	}
	defer os.Remove(file)
	// Start the bridge without mixing its socket-only output into SSH stdout.
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	bridge := exec.Command(exe, "--config", o.Config, "_device-bridge", file)
	if e = bridge.Start(); e != nil {
		return e
	}
	defer func() { bridge.Process.Signal(syscall.SIGTERM); bridge.Wait() }()
	socket, e := managedSocket(s)
	if e != nil {
		return e
	}
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		conn, e := net.DialTimeout("unix", socket, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return errors.New("SSH bridge did not start")
	}
	authorization, _, e := c.Authorization(p, state)
	if e != nil {
		return e
	}
	scope, cancel := context.WithDeadline(ctx, authorization.ExpiresAt)
	defer cancel()
	temp, e := os.MkdirTemp("", "grexie-vault-ssh-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(temp)
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	config, e := prepareManagedSSH(temp, home, "/etc/ssh/ssh_config", socket, authorization.PublicKey, args, cmd)
	if e != nil {
		return e
	}
	native := []string{"-F", config}

	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	native = append(native, args...)
	child := exec.CommandContext(scope, cmd, native...)
	child.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	return child.Run()
}
func managedCrypt(ctx context.Context, o vaultOptions, cmd string, args []string) error {
	f := flags(cmd)
	out := f.String("output", "-", "output file or stdout")
	f.StringVar(out, "o", "-", "output file or stdout")
	armored := f.Bool("armor", false, "ASCII armor")
	var recipients stringsFlag
	f.Var(&recipients, "recipient", "public recipient")
	f.Var(&recipients, "r", "public recipient")
	f.StringVar(&o.Session, "session", o.Session, "existing age session")
	f.StringVar(&o.Reason, "reason", o.Reason, "one-shot decryption reason")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() > 1 {
		return errors.New("one input file or stdin is supported")
	}
	input := "-"
	if f.NArg() == 1 {
		input = f.Arg(0)
	}
	if cmd == "encrypt" {
		if len(recipients) == 0 {
			c, e := loadVault(o)
			if e != nil {
				return e
			}
			records, e := c.Catalog(ctx)
			if e != nil {
				return e
			}
			for _, r := range records {
				if r.Type == "ssh" && (o.Identity == "" || r.Name == o.Identity) {
					recipients = append(recipients, r.PublicKey)
				}
			}
			if len(recipients) != 1 {
				return errors.New("select one SSH identity with --identity or supply public --recipient")
			}
		}
		parsed := []age.Recipient{}
		for _, s := range recipients {
			r, e := ageio.ParseRecipient(s)
			if e != nil {
				return e
			}
			parsed = append(parsed, r)
		}
		return cryptFiles(input, *out, func(dst io.Writer, src io.Reader) error { return ageio.Encrypt(dst, src, parsed, *armored) })
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	managedSettings(&o, c)
	return cryptFiles(input, *out, func(dst io.Writer, src io.Reader) error {
		return ageio.Decrypt(dst, src, func(header []byte) ([]byte, error) {
			var p device.Pending
			var state vaultwire.RequestState
			endpoint := o.AgentURL
			if o.Session != "" {
				saved, e := readManaged(o)
				if e != nil {
					return nil, e
				}
				if saved.Pending.Request.Kind != "age" {
					return nil, errors.New("session does not allow age decryption")
				}
				p = saved.Pending
				endpoint = saved.Endpoint
				state, e = c.Status(ctx, p.Request.ID)
				if e != nil {
					return nil, e
				}
			} else {
				if len(strings.TrimSpace(o.Reason)) < 8 {
					return nil, errors.New("one-shot decryption requires --reason")
				}
				q := requestSpec(o, "age", o.Identity, "ssh", header)
				q.Managed = true
				q.Duration = 60
				q.AgentID = o.Agent
				p, state, e = waitVault(ctx, c, o, q)
				if e != nil {
					return nil, e
				}
				defer c.CloseRequest(p.Request.ID)
			}
			return managedRPC(ctx, c, endpoint, p, state, "age", header)
		})
	})
}
func managedRPC(ctx context.Context, c *device.Client, endpoint string, p device.Pending, state vaultwire.RequestState, method string, data []byte) ([]byte, error) {
	until := time.Now().Add(15 * time.Second)
	for {
		result, e := c.RPC(ctx, endpoint, p, state, method, data)
		if !errors.Is(e, device.ErrPending) || time.Now().After(until) {
			return result, e
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
