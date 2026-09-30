//go:build unix

package command

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func securityReviewPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestManagedSSHRetainsNativeVaultHostWithoutApprovalHooks(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	dir := filepath.Join(home, ".ssh")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "config"), []byte("Include vault-agent.conf\n Port 2222\nHost *\n ServerAliveInterval 30\n"), 0600)
	os.WriteFile(filepath.Join(dir, "vault-agent.conf"), []byte("Match !final originalhost fixture exec \"false\"\n IdentityAgent SSH_AUTH_SOCK\nMatch !final originalhost fixture !exec \"false\"\n ProxyCommand false\nHost fixture\n HostName 127.0.0.9\n User fixture-user\n IdentityAgent /tmp/wrong.sock\nMatch all # restore caller scope\n"), 0600)
	path, err := prepareManagedSSH(root, home, filepath.Join(root, "system"), "/tmp/approved.sock", securityReviewPublicKey(t), []string{"fixture"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ssh", "-G", "-F", path, "fixture").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"hostname 127.0.0.9\n", "user fixture-user\n", "identityagent /tmp/approved.sock\n", "serveraliveinterval 30\n", "port 2222\n"} {
		if !strings.Contains(string(out), expected) {
			t.Fatalf("missing preserved setting %q", expected)
		}
	}
	if strings.Contains(string(out), "proxycommand false") {
		t.Fatal("wrapper executed native approval hooks")
	}
}

func TestSecurityReviewManagedSSHRejectsIdentityOverrides(t *testing.T) {
	public := securityReviewPublicKey(t)
	for name, args := range map[string][]string{
		"private file":              {"-i", "/nonexistent/private", "fixture"},
		"private attached":          {"-i/nonexistent/private", "fixture"},
		"custom configuration":      {"-F", "/nonexistent/config", "fixture"},
		"agent option":              {"-oIdentityAgent=/nonexistent/agent", "fixture"},
		"identity option":           {"-o", "IdentityFile=/nonexistent/private", "fixture"},
		"case variant":              {"-o", "iDeNtItIeSoNlY=no", "fixture"},
		"certificate option":        {"-oCertificateFile=/nonexistent/cert", "fixture"},
		"password authentication":   {"-oPasswordAuthentication=yes", "fixture"},
		"agent forwarding":          {"-A", "fixture"},
		"control socket":            {"-S/nonexistent/master", "fixture"},
		"grouped private file":      {"-vi", "/nonexistent/private", "fixture"},
		"grouped configuration":     {"-vF", "/nonexistent/config", "fixture"},
		"grouped identity option":   {"-vo", "IdentityFile=/nonexistent/private", "fixture"},
		"grouped attached option":   {"-voIdentityAgent=/nonexistent/agent", "fixture"},
		"grouped forwarding":        {"-vvA", "fixture"},
		"leading wrapper separator": {"--", "-i", "/nonexistent/private", "fixture"},
		"post-destination identity": {"fixture", "-oIdentityFile=/nonexistent/private"},
		"post-destination socket":   {"fixture", "-voIdentityAgent=/nonexistent/agent"},
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			_, err := prepareManagedSSH(root, filepath.Join(root, "home"), filepath.Join(root, "system"), "/nonexistent/approved.sock", public, args)
			if err == nil {
				t.Fatalf("native identity override accepted: %q", args)
			}
		})
	}
}

func TestSecurityReviewManagedSSHAllowsRemoteCommandArguments(t *testing.T) {
	root := t.TempDir()
	_, err := prepareManagedSSH(root, filepath.Join(root, "home"), filepath.Join(root, "system"), "/nonexistent/approved.sock", securityReviewPublicKey(t), []string{"-v", "fixture", "printf", "%s", "-i", "-F", "-oIdentityAgent=remote-command-data"})
	if err != nil {
		t.Fatal("remote command data was treated as native SSH options:", err)
	}
}

func TestSecurityReviewManagedSSHConfigHasOnlyApprovedIdentity(t *testing.T) {
	sshBinary, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("OpenSSH is required for the no-network configuration regression")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	sshDir := filepath.Join(home, ".ssh")
	if err = os.MkdirAll(filepath.Join(sshDir, "conf.d"), 0700); err != nil {
		t.Fatal(err)
	}
	userConfig := "Host fixture\n  HostName 127.0.0.1\n  User fixture-user\n  Port 2222\n  ProxyJump 127.0.0.2\n  IdentityFile /nonexistent/local-private\n  CertificateFile /nonexistent/local-certificate\n  IdentityAgent /nonexistent/unapproved.sock\n  IdentitiesOnly no\n  UseKeychain yes\n  AddKeysToAgent yes\n  ForwardAgent yes\n  ControlMaster auto\n  ControlPath /nonexistent/shared-master\n  PasswordAuthentication yes\n  KbdInteractiveAuthentication yes\n  Include conf.d/*\n"
	files := map[string]string{
		filepath.Join(sshDir, "config"):               userConfig,
		filepath.Join(sshDir, "conf.d", "extra.conf"): "IdentityFile /nonexistent/included-private\nPKCS11Provider /nonexistent/hardware-provider\n",
		filepath.Join(root, "system"):                 "Host *\n  IdentityFile /nonexistent/system-private\n",
	}
	for path, contents := range files {
		if err = os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(root, "approved.sock")
	config, err := prepareManagedSSH(root, home, filepath.Join(root, "system"), socket, securityReviewPublicKey(t), []string{"fixture"})
	if err != nil {
		t.Fatal(err)
	}
	// -G prints OpenSSH's fully resolved settings and never connects.
	output, err := exec.Command(sshBinary, "-G", "-F", config, "fixture").Output()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string][]string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.SplitN(line, " ", 2)
		if len(fields) == 2 {
			values[fields[0]] = append(values[fields[0]], fields[1])
		}
	}
	for name, want := range map[string]string{
		"hostname": "127.0.0.1", "user": "fixture-user", "port": "2222", "proxyjump": "127.0.0.2",
		"identityfile": filepath.Join(root, "identity.pub"), "identityagent": socket, "identitiesonly": "yes",
		"forwardagent": "no", "addkeystoagent": "false", "controlmaster": "false",
		"passwordauthentication": "no", "kbdinteractiveauthentication": "no", "preferredauthentications": "publickey",
	} {
		got := values[name]
		// OpenSSH versions differ in how they format numeric jump addresses.
		if name == "proxyjump" && len(got) == 1 {
			got = []string{strings.Trim(got[0], "[]")}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("OpenSSH %s = %q, want only %q", name, got, want)
		}
	}
	for _, path := range []string{config, filepath.Join(root, "identity.pub")} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Errorf("generated file must have private permissions: %s", path)
		}
	}
	unchanged, err := os.ReadFile(filepath.Join(sshDir, "config"))
	if err != nil || string(unchanged) != userConfig {
		t.Fatal("original SSH configuration changed")
	}
}
