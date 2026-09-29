//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/grexie/remote-ssh-agent/internal/app"
	"github.com/grexie/remote-ssh-agent/internal/bridge"
	"github.com/grexie/remote-ssh-agent/internal/signer"
)

var version = "dev"

func main() {
	// Prevent key material and capabilities from entering core dumps.
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "remote-ssh-agent:", err)
		os.Exit(1)
	}
}
func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(os.Stderr)
	return f
}
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "version", "--version":
		fmt.Println(version)
		return nil
	case "help", "--help", "-h":
		usage()
		return nil
	case "serve":
		return serve(ctx, args[1:])
	case "configure":
		f := flags("configure")
		server := f.String("server", "", "HTTPS URL of the phone app")
		config := f.String("config", bridge.DefaultConfigPath(), "CLI config file")
		stdin := f.Bool("token-stdin", false, "read pairing token from stdin")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		if !*stdin {
			return errors.New("use --token-stdin; tokens must not be put in command arguments")
		}
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 1024))
		if e != nil {
			return e
		}
		defer clear(b)
		if e = bridge.Save(*config, bridge.Config{Server: strings.TrimSuffix(*server, "/"), Token: strings.TrimSpace(string(b))}); e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "CLI configured.")
		return nil
	case "request", "ensure", "revoke", "exec", "ssh-config", "status", "wait":
		f := flags(args[0])
		noWait := f.Bool("no-wait", false, "submit and return JSON without waiting for approval")
		waitTimeout := f.Duration("timeout", 5*time.Minute, "maximum approval wait; timeout revokes the request")
		config := f.String("config", bridge.DefaultConfigPath(), "CLI config file")
		session := f.String("session", "", "session name (required)")
		reason := f.String("reason", "", "justification shown on the phone (required)")
		duration := f.Duration("duration", 0, "grant duration, up to 1h (required)")
		host := f.String("host", "", "SSH config alias")
		hostname := f.String("hostname", "", "actual SSH hostname (optional)")
		if e := f.Parse(args[1:]); e != nil {
			return e
		}
		c, e := bridge.Load(*config)
		if e != nil {
			return e
		}
		if !app.SessionPattern.MatchString(*session) {
			return errors.New("--session is required (1–64 letters, digits, dots, underscores or hyphens)")
		}
		if args[0] == "status" {
			q, e := bridge.Status(ctx, c, *session)
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(q)
		}
		if args[0] == "wait" {
			waitCtx, cancel := context.WithTimeout(ctx, *waitTimeout)
			defer cancel()
			sock, e := bridge.Wait(waitCtx, c, *session, func(m string) { fmt.Fprintln(os.Stderr, m) })
			if e == nil {
				fmt.Println(sock)
			}
			return e
		}

		if args[0] == "revoke" {
			e = bridge.Revoke(ctx, c, *session)
			if e == nil {
				fmt.Fprintln(os.Stderr, "Session revoked.")
			}
			return e
		}
		if len(strings.TrimSpace(*reason)) < 8 || len(*reason) > 1000 || *duration < time.Second || *duration > time.Hour {
			return errors.New("--reason (8–1000 characters) and --duration (1s–1h) are required")
		}
		if args[0] == "ssh-config" {
			return sshConfig(c, *config, *host, *hostname, *session, *reason, *duration)
		}
		if *noWait && args[0] != "request" {
			return errors.New("--no-wait is only valid with request")
		}
		if args[0] == "exec" && len(f.Args()) == 0 {
			return errors.New("exec requires a command after --")
		}
		waitCtx, cancel := context.WithTimeout(ctx, *waitTimeout)
		defer cancel()
		sock, e := bridge.Request(waitCtx, c, *session, *reason, *duration, args[0] == "ensure", *noWait, func(m string) { fmt.Fprintln(os.Stderr, m) })
		if e != nil {
			return e
		}
		if *noWait {
			q, e := bridge.Status(ctx, c, *session)
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(q)
		}
		if args[0] != "exec" {
			fmt.Println(sock)
			return nil
		}
		defer func() {
			revokeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if e := bridge.Revoke(revokeCtx, c, *session); e != nil {
				fmt.Fprintln(os.Stderr, "Revoke could not be delivered; the grant still expires at its deadline.")
			}
		}()
		command := f.Args()
		if len(command) == 0 {
			return errors.New("exec requires a command after --")
		}
		cmd := exec.CommandContext(ctx, command[0], command[1:]...)
		env := []string{}
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "SSH_AUTH_SOCK=") && !strings.HasPrefix(v, "SSH_AGENT_PID=") {
				env = append(env, v)
			}
		}
		cmd.Env = append(env, "SSH_AUTH_SOCK="+sock)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case "_signer":
		if len(args) != 4 {
			return errors.New("invalid internal signer invocation")
		}
		deadline, e := strconv.ParseInt(args[3], 10, 64)
		if e != nil {
			return e
		}
		return signer.Serve(args[1], args[2], time.Unix(deadline, 0), os.Stdin, os.Stdout)
	case "_bridge":
		var l bridge.Lease
		if e := json.NewDecoder(io.LimitReader(os.Stdin, 128*1024)).Decode(&l); e != nil {
			return e
		}
		return bridge.Run(ctx, l, func() error { return json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": true}) })
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func serve(ctx context.Context, args []string) error {
	f := flags("serve")
	origin := f.String("origin", "http://localhost:8787", "public HTTPS origin (stable passkey RP)")
	listen := f.String("listen", "127.0.0.1:8787", "HTTP listen address")
	data := f.String("data", "data", "BoltDB data directory")
	cert := f.String("tls-cert", "", "TLS certificate PEM")
	key := f.String("tls-key", "", "TLS private key PEM")
	reset := f.Bool("reset-setup", false, "issue a new setup token before an owner is registered")
	if e := f.Parse(args); e != nil {
		return e
	}
	if (*cert == "") != (*key == "") {
		return errors.New("both --tls-cert and --tls-key are required")
	}
	s, e := app.New(app.Config{Origin: *origin, DataDir: *data, ResetSetup: *reset, Version: version})
	if e != nil {
		return e
	}
	defer s.Close()
	server := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	go s.RunJanitor(ctx)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("Remote SSH Agent %s listening on %s (origin %s)", version, *listen, *origin)
	if *cert != "" {
		e = server.ListenAndServeTLS(*cert, *key)
	} else {
		e = server.ListenAndServe()
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
func sshConfig(c bridge.Config, config, host, hostname, session, reason string, d time.Duration) error {
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`).MatchString(host) {
		return errors.New("--host must be a single SSH alias without wildcards")
	}
	if hostname != "" && !regexp.MustCompile(`^[a-zA-Z0-9:][a-zA-Z0-9.:-]*$`).MatchString(hostname) {
		return errors.New("invalid hostname")
	}
	if strings.ContainsAny(reason, "\r\n\x00") {
		return errors.New("SSH config justifications must be a single line")
	}
	alias, e := bridge.Alias(c, session)
	if e != nil {
		return e
	}
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	parts := []string{exe, "ensure", "--config", config, "--session", session, "--reason", reason, "--duration", d.String()}
	for i, p := range parts {
		parts[i] = shellQuote(p)
	}
	command := strings.Join(parts, " ") + " >/dev/null"
	// OpenSSH expands percent tokens even inside shell quotes. Escape them before
	// escaping the outer ssh_config double-quoted exec argument.
	command = strings.ReplaceAll(command, "%", "%%")
	command = strings.ReplaceAll(command, "\\", "\\\\")
	command = strings.ReplaceAll(command, "\"", "\\\"")
	fmt.Printf("# Include this before broader Host rules. Session: %s\nHost %s\n", session, host)
	if hostname != "" {
		fmt.Printf("    HostName %s\n", hostname)
	}
	fmt.Printf("    IdentityAgent %s\n    IdentityFile none\n    IdentitiesOnly no\n    PreferredAuthentications publickey\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    ForwardAgent no\n    AddKeysToAgent no\nMatch originalhost %s exec \"%s\"\nMatch all\n", strconv.Quote(alias), host, command)
	return nil
}
func usage() {
	fmt.Print(`Remote SSH Agent — one Go binary for phone approval and SSH sockets.

  serve       Host the embedded PWA and BoltDB metadata
  configure   Pair this CLI using --server URL --token-stdin
  request     --session NAME --reason TEXT --duration 15m
  ensure      Reuse a matching grant, or request approval
  status      --session NAME (JSON; safe for polling)
  wait        --session NAME [--timeout 5m]
  revoke      --session NAME
  exec        --session NAME --reason TEXT --duration 15m -- COMMAND ARGS...
  ssh-config  --host ALIAS --session NAME --reason TEXT --duration 15m
  version

request --no-wait returns a pending request as JSON for later status/wait.
request/ensure print only the dedicated SSH_AUTH_SOCK path to stdout.
exec supplies SSH_AUTH_SOCK to its command and revokes when the command exits.
Every new grant needs an explicit justification, duration, and phone approval.
`)
}
