//go:build unix

package provider

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Run intentionally releases credentials to one child process. It does not
// change the parent environment or persist login state in the user's config.
// The child (and its descendants, same-user processes and root) is trusted.
func Run(ctx context.Context, p Profile, c Credentials, args []string, in io.Reader, out, errOut io.Writer) error {
	if e := p.ValidateCredentials(c); e != nil {
		return e
	}
	if p.CLI == nil {
		return errors.New("provider has no CLI integration")
	}
	executable, e := exec.LookPath(p.CLI.Executable)
	if e != nil {
		return errors.New("provider CLI is not installed: " + p.CLI.Executable)
	}
	dir, e := os.MkdirTemp("", "grexie-vault-command-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	values := map[string]string{}
	for n, f := range p.CLI.Env {
		values[n] = c.Fields[f]
	}
	// Do not let cached credentials or debug logs defeat the selected identity.
	strip := func(n string) bool {
		if _, ok := values[n]; ok {
			return true
		}
		switch p.Name {
		case "aws":
			return strings.HasPrefix(n, "AWS_")
		case "github":
			return strings.HasPrefix(n, "GH_") || strings.HasPrefix(n, "GITHUB_") || n == "DEBUG"
		case "docker":
			return n == "DOCKER_CONFIG" || n == "DOCKER_AUTH_CONFIG"
		case "cloudflare":
			return strings.HasPrefix(n, "CLOUDFLARE_") || strings.HasPrefix(n, "CF_")
		}
		return false
	}
	switch p.Name {
	case "aws":
		// The isolated config also disables profiles/credential_process fallback.
		values["AWS_CONFIG_FILE"] = filepath.Join(dir, "config")
		values["AWS_SHARED_CREDENTIALS_FILE"] = filepath.Join(dir, "credentials")
		values["AWS_EC2_METADATA_DISABLED"] = "true"
		values["AWS_CLI_AUTO_PROMPT"] = "off"
		if e = os.WriteFile(values["AWS_CONFIG_FILE"], nil, 0600); e != nil {
			return e
		}
		if e = os.WriteFile(values["AWS_SHARED_CREDENTIALS_FILE"], nil, 0600); e != nil {
			return e
		}
	case "github":
		values["GH_CONFIG_DIR"] = dir
		values["GH_HOST"] = "github.com"
		values["GH_PROMPT_DISABLED"] = "1"
		values["GH_NO_UPDATE_NOTIFIER"] = "1"
		values["GH_NO_EXTENSION_UPDATE_NOTIFIER"] = "1"
	case "docker":
		values["DOCKER_CONFIG"] = dir
		extra, closeHelper, e := dockerHelper(ctx, dir, c)
		if e != nil {
			return e
		}
		defer closeHelper()
		for k, v := range extra {
			values[k] = v
		}

	}
	env := []string{}
	for _, s := range os.Environ() {
		n, _, _ := strings.Cut(s, "=")
		if !strip(n) {
			env = append(env, s)
		}
	}
	for n, v := range values {
		if v != "" {
			env = append(env, n+"="+v)
		}
	}
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = env
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = errOut
	return cmd.Run()
}
