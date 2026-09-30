//go:build unix

package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/vaultwire"
	"golang.org/x/sys/unix"
)

func nativeSSHCommand(ctx context.Context, o vaultOptions, cmd string, args []string) error {
	f := flags(cmd)
	f.StringVar(&o.Config, "config", o.Config, "local device configuration")
	f.StringVar(&o.Session, "session", o.Session, "native SSH session name")
	f.StringVar(&o.Identity, "identity", o.Identity, "named SSH identity")
	f.StringVar(&o.Reason, "reason", o.Reason, "justification shown for approval")
	f.StringVar(&o.Agent, "agent", o.Agent, "paired signing device ID")
	f.StringVar(&o.AgentURL, "agent-url", o.AgentURL, "signing device HTTPS endpoint")
	f.DurationVar(&o.Duration, "duration", o.Duration, "maximum approval duration")
	f.DurationVar(&o.Timeout, "timeout", o.Timeout, "approval wait timeout")
	inherit := f.Bool("inherit-socket", false, "reuse a verified Vault SSH_AUTH_SOCK")
	host := f.String("host", "", "single SSH alias")
	hostname := f.String("hostname", "", "optional destination hostname")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || (*inherit && cmd != "ensure") {
		return errors.New("unexpected native SSH options")
	}
	var e error
	o.Config, e = filepath.Abs(o.Config)
	if e != nil {
		return e
	}
	if cmd == "_ssh-inherited" {
		// Select the exact inherited path locally. Authorization happens once in
		// ensure; two network checks could disagree and select the wrong socket.
		if !nativeSocketCandidate(os.Getenv("SSH_AUTH_SOCK")) {
			return errNoInheritedSocket
		}
		return nil
	}
	if !managedSession.MatchString(o.Session) || o.Identity == "" || len(strings.TrimSpace(o.Reason)) < 8 || len(o.Reason) > 1000 || strings.ContainsAny(o.Reason+o.Identity, "\r\n\x00") || o.Duration < time.Second || o.Duration > 48*time.Hour || o.Timeout < time.Second || o.Timeout > 15*time.Minute {
		return errors.New("supply --session, --identity, a single-line --reason (8–1000 characters), --duration (1s–48h) and --timeout (1s–15m)")
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	managedSettings(&o, c)
	if e = device.ValidateServer(o.AgentURL); e != nil {
		return e
	}
	if cmd == "ssh-config" {
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		alias, e := nativeSocketAlias(o)
		if e != nil {
			return e
		}
		return renderNativeSSH(os.Stdout, exe, alias, *host, *hostname, o)
	}
	wait, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if *inherit && nativeSocketCandidate(os.Getenv("SSH_AUTH_SOCK")) {
		if e := validateInheritedNative(wait, o, c, os.Getenv("SSH_AUTH_SOCK")); e != nil {
			return e // Recognized but invalid is terminal, never a replacement approval.
		}
		fmt.Fprintln(os.Stdout, os.Getenv("SSH_AUTH_SOCK"))
		return nil
	}
	return ensureNativeSSH(wait, o, c, os.Stdout)
}

func nativeSocketAlias(o vaultOptions) (string, error) {
	dir, e := managedRuntimeDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(dir, "host-"+vaultwire.Digest([]byte(o.Config + ":" + o.Session))[:24]+".sock"), nil
}

func nativeSocketCandidate(socket string) bool {
	if socket == "" {
		return false
	}
	p := filepath.Clean(socket)
	// Recognize stale paths too, and explicitly refuse inherited legacy sockets.
	for _, root := range []string{"/tmp", "/private/tmp"} {
		for _, prefix := range []string{"grexie-vault", "remote-ssh"} {
			if strings.HasPrefix(p, fmt.Sprintf("%s/%s-%d/", root, prefix, os.Getuid())) {
				return true
			}
		}
	}
	return false
}

func validateNativeScope(o vaultOptions, c *device.Client, s savedSession, inherited bool) error {
	q := s.Pending.Request
	var signed vaultwire.Request
	if vaultwire.Verify(c.Config.Device.PublicKey, "request", s.Pending.Signed, &signed) != nil || !reflect.DeepEqual(q, signed) || s.Config != o.Config || s.Endpoint != o.AgentURL || q.DeviceID != c.Config.Device.ID || q.AgentID != o.Agent || q.Identity != o.Identity || q.IdentityType != "ssh" || q.Kind != "ssh" || !q.Managed || len(q.Payload) != 0 {
		return errors.New("saved SSH request does not match this device, identity or signing agent")
	}
	if !inherited && (q.Session != o.Session || q.Reason != o.Reason || q.Duration != int64(o.Duration/time.Second)) {
		return errors.New("session already has a different justification or duration; revoke it or choose another session name")
	}
	return nil
}

func validateInheritedNative(ctx context.Context, o vaultOptions, c *device.Client, socket string) error {
	dir, e := managedRuntimeDir()
	if e != nil {
		return e
	}
	realDir, e := filepath.EvalSymlinks(dir)
	if e != nil {
		return e
	}
	target, e := filepath.EvalSymlinks(socket)
	if e != nil || filepath.Dir(target) != realDir {
		return errors.New("inherited Vault socket is unavailable or belongs to the retired agent")
	}
	st, e := os.Lstat(target)
	if e != nil {
		return e
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 {
		return errors.New("inherited Vault socket has unsafe ownership or permissions")
	}
	files, e := filepath.Glob(filepath.Join(filepath.Dir(o.Config), "sessions", "*.json"))
	if e != nil {
		return e
	}
	for _, file := range files {
		candidate := o
		candidate.Session = strings.TrimSuffix(filepath.Base(file), ".json")
		s, e := readManaged(candidate)
		if e != nil {
			continue
		}
		expected, e := managedSocket(s)
		if e != nil || filepath.Base(expected) != filepath.Base(target) {
			continue
		}
		if e := validateNativeScope(o, c, s, true); e != nil {
			return e
		}
		state, e := c.Status(ctx, s.Pending.Request.ID)
		if e != nil {
			return e
		}
		if _, e = c.RPC(ctx, s.Endpoint, s.Pending, state, "ping", nil); e != nil {
			return e
		}
		conn, e := net.DialTimeout("unix", target, time.Second)
		if e != nil {
			return e
		}
		return conn.Close()
	}
	return errors.New("inherited Vault socket has no matching approved local request")
}

func nativeSessionLock(ctx context.Context, path string) (*os.File, error) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		f.Close()
		return nil, errors.New("unsafe native SSH session lock")
	}
	for {
		e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if e == nil {
			return f, nil
		}
		if !errors.Is(e, unix.EWOULDBLOCK) && !errors.Is(e, unix.EAGAIN) {
			f.Close()
			return nil, e
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func ensureNativeSSH(ctx context.Context, o vaultOptions, c *device.Client, output io.Writer) error {
	alias, e := nativeSocketAlias(o)
	if e != nil {
		return e
	}
	file, e := managedFile(o)
	if e != nil {
		return e
	}
	// Lock the saved state, not the config-derived alias: two configs in one
	// directory currently share a sessions directory.
	if e = os.MkdirAll(filepath.Dir(file), 0700); e != nil {
		return e
	}
	if st, err := os.Lstat(filepath.Dir(file)); err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return errors.New("unsafe native SSH session directory")
	}
	lock, e := nativeSessionLock(ctx, file+".lock")
	if e != nil {
		return e
	}
	defer lock.Close() // flock is released only after waiting and publishing the alias.
	s, e := readManaged(o)
	reuse := false
	if e == nil {
		if e = validateNativeScope(o, c, s, false); e != nil {
			return e
		}
		state, e := c.Status(ctx, s.Pending.Request.ID)
		var apiError *device.APIError
		if e != nil && !(errors.As(e, &apiError) && apiError.Status == 404 && nativeExpired(c, s, time.Now())) {
			return e // A network failure is not permission to replace an approval.
		}
		if e == nil {
			switch state.Status {
			case "pending":
				reuse = time.Now().Before(s.Pending.Request.ExpiresAt)
			case "approved":
				a, _, err := c.Authorization(s.Pending, state)
				if err == nil {
					reuse = true
				} else if state.Authorization != nil && vaultwire.Verify(c.Config.OwnerPublic, "authorization", *state.Authorization, &a) == nil && a.RequestID == s.Pending.Request.ID && a.RequestHash == vaultwire.Digest(s.Pending.Signed.Payload) && !time.Now().Before(a.ExpiresAt) {
					// A signed, expired approval may be replaced by a fresh request.
				} else {
					return err
				}
			case "declined", "revoked", "completed":
			default:
				return errors.New("unexpected native SSH request status")
			}
		}
	} else {
		file, err := managedFile(o)
		if err != nil {
			return err
		}
		if _, err = os.Lstat(file); !os.IsNotExist(err) {
			return e // Do not overwrite malformed or unsafe saved state.
		}
	}
	if !reuse {
		q := requestSpec(o, "ssh", o.Identity, "ssh", nil)
		q.Managed = true
		p, e := c.Submit(ctx, q)
		if e != nil {
			return e
		}
		s = savedSession{Config: o.Config, Endpoint: o.AgentURL, Pending: p}
		file, _ := managedFile(o)
		raw, _ := json.Marshal(s)
		if e = device.SavePrivate(file, raw); e != nil {
			c.CloseRequest(p.Request.ID)
			return e
		}
	}
	if e = waitManagedOutput(ctx, o, c, s, io.Discard); e != nil {
		if !reuse {
			c.CloseRequest(s.Pending.Request.ID)
		}
		return e
	}
	state, e := c.Status(ctx, s.Pending.Request.ID)
	if e != nil {
		return e
	}
	if _, _, e = c.Authorization(s.Pending, state); e != nil {
		return e
	}
	s.Authorization = state.Authorization
	raw, _ := json.Marshal(s)
	if e = device.SavePrivate(file, raw); e != nil {
		return e
	}
	socket, e := managedSocket(s)
	if e != nil {
		return e
	}
	// The stable path is only an alias. Each approval keeps its own dedicated
	// socket, which the bridge removes on revocation, expiry or lost contact.
	temp := alias + "." + device.RandomID()
	if e = os.Symlink(socket, temp); e != nil {
		return e
	}
	defer os.Remove(temp)
	if e = os.Rename(temp, alias); e != nil {
		return e
	}
	_, e = fmt.Fprintln(output, alias)
	return e
}

// A missing cloud record proves nothing on its own. Renewal requires a past
// owner-signed deadline, or the latest possible expiry of the signed request.
func nativeExpired(c *device.Client, s savedSession, now time.Time) bool {
	q := s.Pending.Request
	if s.Authorization != nil {
		var a vaultwire.Authorization
		return vaultwire.Verify(c.Config.OwnerPublic, "authorization", *s.Authorization, &a) == nil && a.RequestID == q.ID && a.RequestHash == vaultwire.Digest(s.Pending.Signed.Payload) && vaultwire.ID(a.AgentPublic) == q.AgentID && !now.Before(a.ExpiresAt)
	}
	return !now.Before(q.ExpiresAt.Add(time.Duration(q.Duration) * time.Second))
}

func renderNativeSSH(w io.Writer, exe, alias, host, hostname string, o vaultOptions) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`).MatchString(host) || (hostname != "" && !regexp.MustCompile(`^[a-zA-Z0-9:][a-zA-Z0-9.:-]*$`).MatchString(hostname)) {
		return errors.New("supply a single --host alias without wildcards and a valid optional --hostname")
	}
	if strings.ContainsAny(exe+alias+o.Config+o.Identity+o.Reason+o.Agent+o.AgentURL, "\r\n\x00") {
		return errors.New("native SSH configuration values must be single-line")
	}
	command := matchCommand(exe, "--config", o.Config, "ensure", "--inherit-socket", "--session", o.Session, "--identity", o.Identity, "--reason", o.Reason, "--duration", o.Duration.String(), "--timeout", o.Timeout.String(), "--agent", o.Agent, "--agent-url", o.AgentURL)
	inherited := matchCommand(exe, "--config", o.Config, "_ssh-inherited")
	fmt.Fprintf(w, "# Managed by Grexie Vault. Session: %s\n", o.Session)
	// The final qualifier requests a reparse; its negation runs these hooks
	// only during the first pass, including with hostname canonicalization.
	fmt.Fprintf(w, "Match !final originalhost %s exec \"%s\"\n    IdentityAgent SSH_AUTH_SOCK\n", host, inherited)
	fmt.Fprintf(w, "Match !final originalhost %s !exec \"%s\"\n    ProxyCommand false\n    IdentityAgent none\n", host, command)
	fmt.Fprintf(w, "Host %s\n", host)
	if hostname != "" {
		fmt.Fprintf(w, "    HostName %s\n", hostname)
	}
	// These settings require removing additive private IdentityFile and
	// CertificateFile entries in other applicable rules (see the public skill).
	fmt.Fprintf(w, "    IgnoreUnknown UseKeychain\n    IdentityAgent %s\n    IdentityFile none\n    CertificateFile none\n    IdentitiesOnly no\n    PKCS11Provider none\n    SecurityKeyProvider internal\n    PreferredAuthentications publickey\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    GSSAPIAuthentication no\n    HostbasedAuthentication no\n    ForwardAgent no\n    AddKeysToAgent no\n    UseKeychain no\n    ControlMaster no\n    ControlPath none\n    ControlPersist no\nMatch all\n", strconv.Quote(strings.ReplaceAll(alias, "%", "%%")))
	return nil
}
