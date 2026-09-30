//go:build unix

package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/grexie/vault/internal/bridge"
	"github.com/grexie/vault/internal/limits"
)

func grantCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("use grant create or grant export; revoke/status/wait use --session as usual")
	}
	f := flags("grant " + args[0])
	config := f.String("config", bridge.DefaultConfigPath(), "paired CLI configuration")
	session := f.String("session", "", "persistent grant session name")
	reason := f.String("reason", "", "justification shown on the phone")
	idle := f.String("idle-timeout", "30d", "lock after inactivity; supports d, h, m, s (1s–365d)")
	noWait := f.Bool("no-wait", false, "submit approval and return immediately")
	timeout := f.Duration("timeout", 5*time.Minute, "approval wait timeout")
	repo := f.String("github-repo", "", "write connection token to this OWNER/REPO using gh")
	secret := f.String("secret", "REMOTE_SSH_CONNECTION", "GitHub Actions secret name")
	environment := f.String("environment", "", "optional GitHub deployment environment")
	stdout := f.Bool("token-stdout", false, "explicitly export the secret token to stdout")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if len(f.Args()) != 0 {
		return errors.New("unexpected positional arguments")
	}
	if args[0] != "create" && args[0] != "export" {
		return errors.New("use grant create or grant export")
	}
	if args[0] == "create" && (*repo != "" || *stdout) {
		return errors.New("export the token separately after approval")
	}
	if args[0] == "export" && ((*repo == "") == !*stdout) {
		return errors.New("choose --github-repo OWNER/REPO or --token-stdout")
	}
	if *repo != "" && (!regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`).MatchString(*repo) || !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(*secret)) {
		return errors.New("invalid GitHub repository or secret name")
	}
	c, e := bridge.Load(*config)
	if e != nil {
		return e
	}
	if args[0] == "create" {
		idleDuration, e := parseIdleDuration(*idle)
		if e != nil {
			return e
		}
		wait, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		q, e := bridge.Grant(wait, c, *session, *reason, idleDuration, *noWait, func(m string) { fmt.Fprintln(os.Stderr, m) })
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(q)
	}
	token, e := bridge.ExportGrant(ctx, c, *session)
	if e != nil {
		return e
	}
	if *stdout {
		fmt.Println(token)
		return nil
	}
	ghArgs := []string{"secret", "set", *secret, "--repo", *repo, "--app", "actions"}
	if *environment != "" {
		ghArgs = append(ghArgs, "--env", *environment)
	}
	cmd := exec.CommandContext(ctx, "gh", ghArgs...)
	cmd.Stdin = strings.NewReader(token)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if e = cmd.Run(); e != nil {
		return errors.New("gh secret set failed; the grant remains available for export or revocation")
	}
	fmt.Fprintln(os.Stderr, "Connection token saved to GitHub Actions secret "+*secret+".")
	return nil
}

func connectCommand(ctx context.Context, args []string) error {
	f := flags("connect")
	stdin := f.Bool("token-stdin", false, "read the persistent connection token from stdin")
	config := f.String("config", "", "new private config path for this job (required)")
	session := f.String("session", "", "unique job/session name (required)")
	timeout := f.Duration("timeout", 5*time.Minute, "maximum wait for approval after inactivity")
	duration := f.Duration("duration", time.Hour, "connection lifetime, up to 48h")
	if e := f.Parse(args); e != nil {
		return e
	}
	if !*stdin || *config == "" {
		return errors.New("--token-stdin and a new --config path are required")
	}
	b, e := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if e != nil {
		return e
	}
	defer clear(b)
	if len(b) > 4096 {
		return errors.New("connection token is too large")
	}
	t, e := bridge.ParseConnectionToken(strings.TrimSpace(string(b)))
	if e != nil {
		return e
	}
	wait, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	fmt.Fprintln(os.Stderr, "Connecting; if the grant is locked, waiting for phone approval…")
	sock, c, e := bridge.Connect(wait, t, *config, *session, *duration)
	if e != nil {
		return e
	}
	if len(f.Args()) == 0 {
		fmt.Println(sock)
		return nil
	}
	defer func() {
		revoke, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if e := bridge.Revoke(revoke, c, *session); e != nil {
			fmt.Fprintln(os.Stderr, "Connection cleanup failed; it still expires at its deadline.")
		} else {
			os.Remove(*config)
		}
	}()
	cmd := exec.CommandContext(ctx, f.Args()[0], f.Args()[1:]...)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "SSH_AUTH_SOCK=") && !strings.HasPrefix(v, "SSH_AGENT_PID=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+sock)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// stdin was consumed by the token; commands may read their data from files.
	return cmd.Run()
}

func parseIdleDuration(value string) (time.Duration, error) {
	days := strings.HasSuffix(value, "d")
	if days {
		value = strings.TrimSuffix(value, "d") + "h"
	}
	d, e := time.ParseDuration(value)
	if e != nil {
		return 0, errors.New("invalid inactivity duration; use for example 30d or 12h")
	}
	if days {
		if d > limits.MaxIdleDuration/24 {
			return 0, errors.New("inactivity timeout must be 1s–365d")
		}
		d *= 24
	}
	if d < time.Second || d > limits.MaxIdleDuration {
		return 0, errors.New("inactivity timeout must be 1s–365d")
	}
	return d, nil
}
