//go:build unix

package command

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/vaultwire"
)

func TestNativeSSHOpenSSHConfig(t *testing.T) {
	ssh, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH required")
	}
	for _, tc := range []struct {
		name, inherited, approved, agent, proxy string
	}{
		{"approved host", "1", "0", "/tmp/fixture-host.sock", ""},
		{"inherited task", "0", "0", "SSH_AUTH_SOCK", ""},
		{"declined host", "1", "1", "none", "false"},
		{"invalid inherited task", "0", "1", "SSH_AUTH_SOCK", "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			helper := filepath.Join(dir, "vault with spaces%quote'")
			log := filepath.Join(dir, "calls")
			// Exercise the actual shell quoting and OpenSSH Match parser. No SSH
			// connection or Vault API is needed to inspect effective settings.
			script := "#!/bin/sh\nif [ \"$1\" != --config ]; then exit 9; fi\nprintf '%s\\n' \"$3\" >> \"$TEST_CALLS\"\ncase \"$3\" in\n_ssh-inherited) exit \"$TEST_INHERITED\";;\nensure) printf '%s\\n' \"$@\" > \"$TEST_ARGS\"; exit \"$TEST_APPROVED\";;\nesac\nexit 9\n"
			if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			reason := "Inspect user's deployment with 20% progress and literal $(false)"
			o := vaultOptions{Config: filepath.Join(dir, "config with spaces.json"), Identity: "work", Session: "ssh-fixture", Reason: reason, Agent: "agent-id", AgentURL: "https://agent.invalid", Duration: 15 * time.Minute, Timeout: time.Minute}
			var config bytes.Buffer
			if err := renderNativeSSH(&config, helper, "/tmp/fixture-host.sock", "fixture", "127.0.0.1", o); err != nil {
				t.Fatal(err)
			}
			config.WriteString("Host fixture\n  User fixture-user\n  ProxyJump jump-fixture\nMatch final\n  ServerAliveInterval 30\n")
			path := filepath.Join(dir, "ssh_config")
			if err := os.WriteFile(path, config.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(ssh, "-T", "-G", "-F", path, "fixture")
			command.Env = append(os.Environ(), "SSH_AUTH_SOCK=/tmp/fixture-task.sock", "TEST_CALLS="+log, "TEST_ARGS="+log+".args", "TEST_INHERITED="+tc.inherited, "TEST_APPROVED="+tc.approved)
			out, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("OpenSSH config: %v\n%s", err, out)
			}
			for _, expected := range []string{"identityagent " + tc.agent, "identityfile none", "certificatefile none", "hostname 127.0.0.1", "user fixture-user", "forwardagent no", "passwordauthentication no", "kbdinteractiveauthentication no", "controlmaster false", "serveraliveinterval 30"} {
				if !strings.Contains(string(out), expected+"\n") {
					t.Errorf("missing effective setting %q\n%s", expected, out)
				}
			}
			if tc.proxy != "" && !strings.Contains(string(out), "proxycommand false\n") {
				t.Fatal("failed approval did not block transport")
			}
			if tc.proxy == "" && !strings.Contains(string(out), "proxyjump jump-fixture\n") {
				t.Fatal("approved connection lost ProxyJump")
			}
			calls, _ := os.ReadFile(log)
			if string(calls) != "_ssh-inherited\nensure\n" {
				t.Fatalf("hooks must run once despite final reparse: %q", calls)
			}
			args, _ := os.ReadFile(log + ".args")
			if !strings.Contains(string(args), "\n"+reason+"\n") || !strings.Contains(string(args), "\n"+o.Config+"\n") {
				t.Fatalf("shell quoting changed arguments: %s", args)
			}
		})
	}
}

func nativeFixture(t *testing.T, server string) (vaultOptions, *device.Client, savedSession) {
	t.Helper()
	cfg, err := device.NewConfig(server, "native-test")
	if err != nil {
		t.Fatal(err)
	}
	cfg.OwnerID = "fixture-owner"
	owner, err := vaultwire.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg.OwnerPublic = owner.PublicKey().Bytes()
	o := vaultOptions{Config: filepath.Join(t.TempDir(), "config.json"), Identity: "work", Session: "ssh-fixture", Reason: "Read deployment logs", Agent: "agent-id", AgentURL: "https://agent.invalid", Duration: 15 * time.Minute, Timeout: time.Second}
	q := requestSpec(o, "ssh", o.Identity, "ssh", nil)
	q.ID, q.DeviceID, q.Managed = device.RandomID(), cfg.Device.ID, true
	q.CreatedAt = time.Now().UTC()
	q.ExpiresAt = q.CreatedAt.Add(10 * time.Minute)
	signed, err := vaultwire.Sign(cfg.PrivateKey, "request", q)
	if err != nil {
		t.Fatal(err)
	}
	return o, device.New(cfg), savedSession{Config: o.Config, Endpoint: o.AgentURL, Pending: device.Pending{Request: q, Signed: signed}}
}

func TestNativeSSHReuseScope(t *testing.T) {
	o, c, s := nativeFixture(t, "https://vault.invalid")
	if err := validateNativeScope(o, c, s, false); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*vaultOptions){
		func(o *vaultOptions) { o.Identity = "other" },
		func(o *vaultOptions) { o.Agent = "other" },
		func(o *vaultOptions) { o.AgentURL = "https://other.invalid" },
		func(o *vaultOptions) { o.Config += ".other" },
		func(o *vaultOptions) { o.Reason = "Different task" },
		func(o *vaultOptions) { o.Duration *= 2 },
		func(o *vaultOptions) { o.Session = "other-session" },
	} {
		other := o
		change(&other)
		if err := validateNativeScope(other, c, s, false); err == nil {
			t.Fatal("mismatched host lease was reusable")
		}
	}
	task := o
	task.Session, task.Reason, task.Duration = "task-session", "Task-specific justification", time.Hour
	if err := validateNativeScope(task, c, s, true); err != nil {
		t.Fatal("valid explicit task lease cannot be inherited:", err)
	}
	s.Pending.Request.Kind = "age"
	if err := validateNativeScope(o, c, s, true); err == nil {
		t.Fatal("modified unsigned request accepted")
	}
	s.Pending.Signed, _ = vaultwire.Sign(c.Config.PrivateKey, "request", s.Pending.Request)
	if err := validateNativeScope(o, c, s, true); err == nil {
		t.Fatal("signed age-only request accepted for SSH")
	}
}

func TestNativeSSHInheritedRejectsRevokedAndStale(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.Contains(r.URL.Path, "/device/requests/") {
			t.Error("invalid inherited lease attempted another operation:", r.URL.Path)
		}
		json.NewEncoder(w).Encode(vaultwire.RequestState{Status: "revoked"})
	}))
	defer server.Close()
	o, c, s := nativeFixture(t, server.URL)
	file, _ := managedFile(o)
	raw, _ := json.Marshal(s)
	if err := device.SavePrivate(file, raw); err != nil {
		t.Fatal(err)
	}
	socket, err := managedSocket(s)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	os.Chmod(socket, 0600)
	if err := validateInheritedNative(context.Background(), o, c, socket); err == nil || calls != 1 {
		t.Fatalf("revoked inherited socket accepted: %v, calls=%d", err, calls)
	}
	listener.Close()
	if err := validateInheritedNative(context.Background(), o, c, socket); err == nil || calls != 1 {
		t.Fatal("stale socket was accepted or silently renewed")
	}
	if !nativeSocketCandidate(socket) || nativeSocketCandidate("/tmp/ordinary-ssh-agent.sock") {
		t.Fatal("managed socket recognition is wrong")
	}
}

func TestNativeSSHNetworkFailureDoesNotReplaceSession(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	o, c, s := nativeFixture(t, server.URL)
	file, _ := managedFile(o)
	raw, _ := json.Marshal(s)
	device.SavePrivate(file, raw)
	alias, _ := nativeSocketAlias(o)
	defer os.Remove(alias + ".lock")
	if err := ensureNativeSSH(context.Background(), o, c, io.Discard); err == nil || calls != 1 {
		t.Fatalf("unverifiable lease was replaced: %v, calls=%d", err, calls)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(raw, after) {
		t.Fatal("saved request changed during network failure")
	}
}

func TestNativeSSHLockSerializesAndRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.lock")
	first, err := nativeSessionLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if second, err := nativeSessionLock(ctx, path); err == nil {
		second.Close()
		t.Fatal("concurrent host requests were not serialized")
	}
	first.Close()
	third, err := nativeSessionLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	third.Close()
	os.Symlink(path, path+".symlink")
	if lock, err := nativeSessionLock(context.Background(), path+".symlink"); err == nil {
		lock.Close()
		t.Fatal("symlink lock accepted")
	}
}

func nativeExpiryProof(t *testing.T, c *device.Client, s *savedSession, deadline time.Time) []byte {
	t.Helper()
	owner, err := vaultwire.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	agent, err := vaultwire.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	c.Config.OwnerPublic = owner.PublicKey().Bytes()
	s.Pending.Request.AgentID = vaultwire.ID(agent.PublicKey().Bytes())
	s.Pending.Signed, err = vaultwire.Sign(c.Config.PrivateKey, "request", s.Pending.Request)
	if err != nil {
		t.Fatal(err)
	}
	a := vaultwire.Authorization{RequestID: s.Pending.Request.ID, RequestHash: vaultwire.Digest(s.Pending.Signed.Payload), AgentPublic: agent.PublicKey().Bytes(), ExpiresAt: deadline}
	proof, err := vaultwire.Sign(owner.Bytes(), "authorization", a)
	if err != nil {
		t.Fatal(err)
	}
	s.Authorization = &proof
	return owner.Bytes()
}

func TestNativeSSHRenewalRequiresAuthenticExpiredDeadline(t *testing.T) {
	_, c, s := nativeFixture(t, "https://vault.invalid")
	now := time.Now().UTC()
	owner := nativeExpiryProof(t, c, &s, now.Add(-time.Second))
	if !nativeExpired(c, s, now) {
		t.Fatal("authentic expired approval did not allow renewal")
	}
	if nativeExpired(c, s, now.Add(-time.Minute)) {
		t.Fatal("live approval was treated as expired")
	}
	original := *s.Authorization
	for _, change := range []func(*vaultwire.Authorization){
		func(a *vaultwire.Authorization) { a.RequestID = "other" },
		func(a *vaultwire.Authorization) { a.RequestHash = "other" },
		func(a *vaultwire.Authorization) { a.AgentPublic = c.Config.Device.PublicKey },
	} {
		var a vaultwire.Authorization
		json.Unmarshal(original.Payload, &a)
		change(&a)
		proof, _ := vaultwire.Sign(owner, "authorization", a)
		s.Authorization = &proof
		if nativeExpired(c, s, now) {
			t.Fatal("wrong request, hash or agent enabled renewal")
		}
	}
	s.Authorization = &original
	oldOwner := c.Config.OwnerPublic
	c.Config.OwnerPublic = c.Config.Device.PublicKey
	if nativeExpired(c, s, now) {
		t.Fatal("wrong owner enabled renewal")
	}
	c.Config.OwnerPublic = oldOwner
	tampered := original
	tampered.Payload = append([]byte(nil), original.Payload...)
	tampered.Payload[0] = ' '
	s.Authorization = &tampered
	if nativeExpired(c, s, now.Add(72*time.Hour)) {
		t.Fatal("invalid present proof fell back to request deadline")
	}
	s.Authorization = nil
	boundary := s.Pending.Request.ExpiresAt.Add(time.Duration(s.Pending.Request.Duration) * time.Second)
	if nativeExpired(c, s, boundary.Add(-time.Second)) || !nativeExpired(c, s, boundary) {
		t.Fatal("missing proof ignored latest possible request expiry")
	}
}

func TestNativeSSHMissingRecordRenewal(t *testing.T) {
	for _, tc := range []struct {
		name           string
		status         int
		expired, renew bool
	}{
		{"live 404", 404, false, false}, {"expired 404", 404, true, true},
		{"expired 403", 403, true, false}, {"expired 503", 503, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			creates := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/device/requests" {
					creates++
					http.Error(w, "fixture stops after renewal submission", 503)
					return
				}
				http.Error(w, "missing or unavailable", tc.status)
			}))
			defer server.Close()
			o, c, s := nativeFixture(t, server.URL)
			deadline := time.Now().Add(time.Minute)
			if tc.expired {
				deadline = time.Now().Add(-time.Minute)
			}
			nativeExpiryProof(t, c, &s, deadline)
			o.Agent = s.Pending.Request.AgentID
			file, _ := managedFile(o)
			raw, _ := json.Marshal(s)
			if err := device.SavePrivate(file, raw); err != nil {
				t.Fatal(err)
			}
			if err := ensureNativeSSH(context.Background(), o, c, io.Discard); err == nil {
				t.Fatal("fixture unexpectedly completed")
			}
			if (creates == 1) != tc.renew {
				t.Fatalf("renewal submissions=%d, want renewal=%v", creates, tc.renew)
			}
		})
	}
}
