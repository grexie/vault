//go:build unix

package command

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var protectedSSH = map[string]bool{"identityfile": true, "identityagent": true, "identitiesonly": true, "certificatefile": true, "pkcs11provider": true, "securitykeyprovider": true, "addkeystoagent": true, "usekeychain": true, "forwardagent": true, "controlmaster": true, "controlpath": true, "controlpersist": true, "passwordauthentication": true, "kbdinteractiveauthentication": true, "challengeresponseauthentication": true, "gssapiauthentication": true, "hostbasedauthentication": true, "preferredauthentications": true, "pubkeyauthentication": true}

// prepareManagedSSH preserves host, jump/proxy and transport options but removes
// every private-key fallback. OpenSSH IdentityFile is additive, so '-o none'
// alone is insufficient. Only the approved PUBLIC key goes into the temp config.
func prepareManagedSSH(dir, home, systemConfig, socket, public string, args []string, modes ...string) (string, error) {
	native := "ssh"
	if len(modes) > 0 {
		native = modes[0]
	}
	if err := validateManagedSSHArgs(native, args); err != nil {
		return "", err
	}

	publicPath := filepath.Join(dir, "identity.pub")
	if strings.ContainsAny(public, "\r\n") || !strings.HasPrefix(public, "ssh-") && !strings.HasPrefix(public, "ecdsa-") {
		return "", errors.New("invalid approved SSH public key")
	}
	if e := os.WriteFile(publicPath, []byte(public+"\n"), 0600); e != nil {
		return "", e
	}
	quote := func(s string) string { return "\"" + strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(s) + "\"" }
	var config strings.Builder
	fmt.Fprintf(&config, "Host *\n  IgnoreUnknown UseKeychain\n  IdentityAgent %s\n  IdentityFile %s\n  IdentitiesOnly yes\n  CertificateFile none\n  PKCS11Provider none\n  AddKeysToAgent no\n  UseKeychain no\n  ForwardAgent no\n  ControlMaster no\n  ControlPath none\n  ControlPersist no\n  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  GSSAPIAuthentication no\n  HostbasedAuthentication no\n  PreferredAuthentications publickey\n  PubkeyAuthentication yes\n", quote(socket), quote(publicPath))
	seen := map[string]bool{}
	total := 0
	var appendConfig func(string, int) error
	appendConfig = func(path string, depth int) error {
		if depth > 12 {
			return errors.New("SSH include nesting exceeds limit")
		}
		absolute, e := filepath.Abs(path)
		if e != nil {
			return e
		}
		if seen[absolute] {
			return nil
		}
		seen[absolute] = true
		// These generated legacy rules request an independent lease through Match
		// exec; this wrapper already has an explicit approved task session.
		if filepath.Base(path) == "remote-agent.conf" {
			return nil
		}
		f, e := os.Open(path)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		defer f.Close()
		scan := bufio.NewScanner(f)
		scan.Buffer(make([]byte, 4096), 128*1024)
		vaultHooks := filepath.Base(path) == "vault-agent.conf"
		inHook := false
		for scan.Scan() {
			line := scan.Text()
			total += len(line)
			if total > 1024*1024 {
				return errors.New("SSH configuration exceeds limit")
			}
			text := strings.TrimSpace(line)
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			fields := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
			if len(fields) == 0 {
				continue
			}
			key := strings.ToLower(fields[0])
			if vaultHooks {
				if key == "match" {
					inHook = true
					if len(fields) >= 2 && strings.EqualFold(fields[1], "all") && (len(fields) == 2 || strings.HasPrefix(fields[2], "#")) {
						config.WriteString("Match all\n")
					}
					continue
				}
				if key == "host" {
					inHook = false
				}
				if inHook {
					continue
				}
			}
			if protectedSSH[key] {
				continue
			}
			if key == "include" {
				for _, pattern := range fields[1:] {
					if strings.HasPrefix(pattern, "#") {
						break
					}
					pattern = strings.Trim(pattern, "\"'")
					if strings.HasPrefix(pattern, "~/") {
						pattern = filepath.Join(home, pattern[2:])
					} else if !filepath.IsAbs(pattern) {
						base := filepath.Join(home, ".ssh")
						if strings.HasPrefix(path, "/etc/ssh/") {
							base = "/etc/ssh"
						}
						pattern = filepath.Join(base, pattern)
					}
					matches, e := filepath.Glob(pattern)
					if e != nil {
						return e
					}
					for _, match := range matches {
						if e = appendConfig(match, depth+1); e != nil {
							return e
						}
					}
				}
				continue
			}
			config.WriteString(line)
			config.WriteByte('\n')
		}
		return scan.Err()
	}
	if e := appendConfig(filepath.Join(home, ".ssh", "config"), 0); e != nil {
		return "", e
	}
	config.WriteString("\nHost *\n")
	if e := appendConfig(systemConfig, 0); e != nil {
		return "", e
	}
	path := filepath.Join(dir, "ssh_config")
	if e := os.WriteFile(path, []byte(config.String()), 0600); e != nil {
		return "", e
	}
	return path, nil
}

// Parse grouped OpenSSH options and stop at SSH's destination, so remote command
// arguments remain untouched. SCP has file operands rather than a remote command.
func validateManagedSSHArgs(native string, args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	valueFlags := "BbcDEeFIiJLlmOoPpQRSWw"
	if native == "scp" {
		valueFlags = "cDFiJloPSX"
	}
	destinationSeen := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if a == "-" || !strings.HasPrefix(a, "-") {
			if native == "ssh" {
				if destinationSeen {
					break
				}
				destinationSeen = true
			}
			continue
		}
		group := a[1:]
		for j := 0; j < len(group); j++ {
			flag := group[j]
			if strings.ContainsRune("iFISA MK", rune(flag)) && flag != ' ' {
				return errors.New("identity overrides, custom SSH programs/configs, forwarding and connection reuse are disabled")
			}
			if !strings.ContainsRune(valueFlags, rune(flag)) {
				continue
			}
			value := group[j+1:]
			if value == "" {
				i++
				if i >= len(args) {
					return errors.New("missing SSH option value")
				}
				value = args[i]
			}
			if flag == 'o' {
				parts := strings.FieldsFunc(value, func(r rune) bool { return r == '=' || r == ' ' || r == '\t' })
				if len(parts) == 0 {
					return errors.New("empty SSH option")
				}
				if protectedSSH[strings.ToLower(parts[0])] {
					return errors.New("SSH identity and authentication options are controlled by Vault")
				}
			}
			break
		}
	}
	return nil
}
