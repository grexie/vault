//go:build unix

package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ImportExisting is only called for an explicit CLI import. Normal wrappers
// never look for credentials outside Vault or fall back to existing logins.
func ImportExisting(ctx context.Context, name, profile, registry string) (Credentials, error) {
	c := Credentials{Provider: name, Fields: map[string]string{}}
	run := func(program string, args []string, input []byte) ([]byte, error) {
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Stdin = bytes.NewReader(input)
		var output limitedBuffer
		cmd.Stdout = &output
		cmd.Stderr = io.Discard
		if e := cmd.Run(); e != nil {
			return nil, errors.New("credential source could not be read; no credentials were imported")
		}
		return output.Bytes(), nil
	}
	switch name {
	case "aws":
		args := []string{"configure", "export-credentials", "--format", "process"}
		if profile != "" {
			args = append(args, "--profile", profile)
		}
		b, e := run("aws", args, nil)
		if e != nil {
			return c, e
		}
		defer clear(b)
		var value struct {
			AccessKeyId     string
			SecretAccessKey string
			SessionToken    string
			Expiration      string
		}
		if json.Unmarshal(b, &value) != nil {
			return c, errors.New("invalid AWS credential response")
		}
		c.Fields["accessKeyId"] = value.AccessKeyId
		c.Fields["secretAccessKey"] = value.SecretAccessKey
		c.Fields["sessionToken"] = value.SessionToken
		// Expiring credentials retain their expiry; importing never makes an STS
		// session permanent. The provider will refuse them when they expire.
		if value.Expiration != "" {
			return c, errors.New("AWS returned temporary credentials; import a renewable provider configuration or supply long-lived credentials explicitly")
		}
		if v := os.Getenv("AWS_REGION"); v != "" {
			c.Fields["region"] = v
		} else if v = os.Getenv("AWS_DEFAULT_REGION"); v != "" {
			c.Fields["region"] = v
		}
	case "github":
		b, e := run("gh", []string{"auth", "token", "--hostname", "github.com"}, nil)
		if e != nil {
			return c, e
		}
		defer clear(b)
		c.Fields["token"] = strings.TrimSpace(string(b))
		c.Fields["host"] = "github.com"
	case "cloudflare":
		c.Fields["token"] = os.Getenv("CLOUDFLARE_API_TOKEN")
		c.Fields["accountId"] = os.Getenv("CLOUDFLARE_ACCOUNT_ID")
		if c.Fields["token"] == "" {
			return c, errors.New("set CLOUDFLARE_API_TOKEN locally or use --stdin JSON")
		}
	case "docker":
		if registry == "" {
			return c, errors.New("--registry is required; Vault does not enumerate all Docker credentials")
		}
		dir := os.Getenv("DOCKER_CONFIG")
		if dir == "" {
			home, e := os.UserHomeDir()
			if e != nil {
				return c, e
			}
			dir = filepath.Join(home, ".docker")
		}
		f, e := os.Open(filepath.Join(dir, "config.json"))
		if e != nil {
			return c, errors.New("Docker configuration could not be read")
		}
		b, e := io.ReadAll(io.LimitReader(f, 1024*1024+1))
		f.Close()
		if e != nil || len(b) > 1024*1024 {
			return c, errors.New("invalid Docker configuration")
		}
		defer clear(b)
		var cfg struct {
			Auths map[string]struct {
				Auth          string `json:"auth"`
				IdentityToken string `json:"identitytoken"`
			} `json:"auths"`
			Store   string            `json:"credsStore"`
			Helpers map[string]string `json:"credHelpers"`
		}
		if json.Unmarshal(b, &cfg) != nil {
			return c, errors.New("invalid Docker configuration")
		}
		helper := cfg.Helpers[registry]
		if helper == "" {
			helper = cfg.Store
		}
		c.Fields["server"] = registry
		if helper != "" {
			if !namePattern.MatchString(helper) {
				return c, errors.New("invalid Docker credential helper name")
			}
			raw, e := run("docker-credential-"+helper, []string{"get"}, []byte(registry+"\n"))
			if e != nil {
				return c, e
			}
			defer clear(raw)
			var value struct {
				Username string
				Secret   string
			}
			if json.Unmarshal(raw, &value) != nil {
				return c, errors.New("invalid Docker credential helper response")
			}
			c.Fields["username"] = value.Username
			c.Fields["password"] = value.Secret
		} else {
			entry := cfg.Auths[registry]
			if entry.IdentityToken != "" {
				return c, errors.New("Docker identity-token import requires a registry-specific provider profile")
			}
			raw, e := base64.StdEncoding.DecodeString(entry.Auth)
			if e != nil {
				return c, errors.New("invalid Docker credential")
			}
			defer clear(raw)
			u, p, ok := strings.Cut(string(raw), ":")
			if !ok {
				return c, errors.New("registry has no stored login")
			}
			c.Fields["username"] = u
			c.Fields["password"] = p
		}
	default:
		return c, errors.New("this provider requires --stdin credential JSON")
	}
	return c, Builtins()[name].ValidateCredentials(c)
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, errors.New("credential source response too large")
	}
	return b.Buffer.Write(p)
}
