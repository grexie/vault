//go:build unix

package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/provider"
	"github.com/grexie/vault/internal/vaultwire"
)

type vaultOptions struct {
	Config, Identity, Session, Reason, Agent, AgentURL string
	Duration, Timeout                                  time.Duration
}

func newVaultCommand(ctx context.Context, args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	recognized := func(s string) bool {
		if !strings.Contains(filepath.Base(os.Args[0]), "remote-ssh-agent") {
			switch s {
			case "request", "wait", "status", "revoke", "encrypt", "decrypt", "ensure", "ssh-config", "_ssh-inherited":
				return true
			}
		}
		switch s {
		case "agent", "_device-bridge", "ssh", "scp", "pair", "provider", "import", "identity", "run", "aws", "gh", "github", "docker", "cloudflare", "wrangler", "autofill", "browser", "card-cvv", "api", "keychain", "sign", "foundry":
			return true
		}
		return false
	}
	if !strings.HasPrefix(args[0], "--") && !recognized(args[0]) {
		return false, nil
	}
	if args[0] == "--help" || args[0] == "--version" {
		return false, nil
	}
	f := flags("vault")
	o := vaultOptions{}
	f.StringVar(&o.Config, "config", device.DefaultConfig(), "local device configuration")
	f.StringVar(&o.Identity, "identity", "", "named identity (unique default if omitted)")
	f.StringVar(&o.Reason, "reason", "", "justification shown for approval")
	f.StringVar(&o.Session, "session", "", "session name")
	f.StringVar(&o.Agent, "agent", "", "paired user-controlled signing device ID")
	f.StringVar(&o.AgentURL, "agent-url", "", "signing device HTTPS endpoint")
	f.DurationVar(&o.Duration, "duration", 15*time.Minute, "maximum access duration (up to 48h)")
	f.DurationVar(&o.Timeout, "timeout", 10*time.Minute, "approval wait timeout")
	if e := f.Parse(args); e != nil {
		return true, e
	}
	rest := f.Args()
	if len(rest) == 0 {
		return true, errors.New("a vault command is required")
	}
	if o.Duration < time.Second || o.Duration > 48*time.Hour || o.Timeout < time.Second || o.Timeout > 15*time.Minute {
		return true, errors.New("duration must be 1s–48h; approval timeout must be 1s–15m")
	}
	cmd, tail := rest[0], rest[1:]
	switch cmd {
	case "ensure", "ssh-config", "_ssh-inherited":
		return true, nativeSSHCommand(ctx, o, cmd, tail)
	case "agent", "_device-bridge", "request", "wait", "status", "revoke", "ssh", "scp", "encrypt", "decrypt":
		return true, managedCommand(ctx, o, cmd, tail)
	case "sign":
		return true, signVault(ctx, o, tail)
	case "foundry":
		return true, foundryVault(ctx, o, tail)
	case "keychain":
		return true, keychainVault(ctx, o, tail)
	case "pair":
		return true, pairVault(ctx, o, tail)
	case "provider":
		return true, providerVault(o, tail)
	case "import":
		return true, importVault(ctx, o, tail)
	case "identity":
		return true, identityVault(ctx, o, tail)
	case "aws", "gh", "github", "docker", "cloudflare", "wrangler":
		return true, wrapVault(ctx, o, provider.Alias(cmd), tail)
	case "run":
		if len(tail) == 0 {
			return true, errors.New("usage: vault run PROVIDER -- ARGS")
		}
		if len(tail) > 1 && tail[1] == "--" {
			tail = append(tail[:1], tail[2:]...)
		}
		return true, wrapVault(ctx, o, provider.Alias(tail[0]), tail[1:])
	case "api":
		return true, apiVault(ctx, o, tail)
	case "autofill", "browser", "card-cvv":
		return true, browserVault(ctx, o, cmd, tail)
	default:
		return true, errors.New("unknown vault command")
	}
}
func pairVault(ctx context.Context, o vaultOptions, args []string) error {
	f := flags("pair")
	server := f.String("server", "https://vault.grexie.com", "Vault HTTPS origin")
	hostname, _ := os.Hostname()
	name := f.String("name", hostname, "device name")
	role := f.String("role", "client", "client or agent: a signing agent is trusted to hold approved private keys")
	resume := f.Bool("resume", false, "wait for an existing pairing")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected pairing arguments")
	}
	var c device.Config
	var e error
	if *resume {
		c, e = device.Load(o.Config)
	} else {
		if _, err := os.Lstat(o.Config); err == nil {
			return errors.New("configuration already exists; use --resume or a different --config")
		}
		if *role != "client" && *role != "agent" {
			return errors.New("device role must be client or agent")
		}
		c, e = device.NewConfig(*server, *name)
		c.Device.Role = *role
	}
	if e != nil {
		return e
	}
	client := device.New(c)
	if !*resume {
		if e = device.Save(o.Config, c); e != nil {
			return e
		}
		code, e := client.Enroll(ctx)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Open", c.Server+"/app", "→ Settings → Connect device, then paste this one-time pairing code:")
		fmt.Fprintln(os.Stdout, code)
	}
	wait, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	for {
		e = client.FinishPair(wait)
		if e == nil {
			if e = device.Save(o.Config, client.Config); e != nil {
				return e
			}
			fmt.Fprintln(os.Stderr, "Device paired. Owner encryption and approval keys are pinned locally.")
			return nil
		}
		if !errors.Is(e, device.ErrPending) {
			return e
		}
		select {
		case <-wait.Done():
			return errors.New("pairing timed out; use vault pair --resume while the code remains valid")
		case <-time.After(2 * time.Second):
		}
	}
}
func loadProfile(o vaultOptions, name string) (provider.Profile, error) {
	if p, ok := provider.Builtins()[name]; ok {
		return p, nil
	}
	if strings.ContainsAny(name, "/\\.") {
		return provider.Profile{}, errors.New("invalid provider name")
	}
	b, e := os.ReadFile(filepath.Join(filepath.Dir(o.Config), "providers", name+".json"))
	if e != nil {
		return provider.Profile{}, errors.New("provider is not installed")
	}
	return provider.Decode(b)
}
func providerVault(o vaultOptions, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vault provider list | show NAME | install FILE.json")
	}
	switch args[0] {
	case "list":
		out := []string{}
		for k := range provider.Builtins() {
			out = append(out, k)
		}
		files, _ := filepath.Glob(filepath.Join(filepath.Dir(o.Config), "providers", "*.json"))
		for _, p := range files {
			out = append(out, strings.TrimSuffix(filepath.Base(p), ".json"))
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	case "show":
		if len(args) != 2 {
			return errors.New("provider name is required")
		}
		p, e := loadProfile(o, provider.Alias(args[1]))
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(p)
	case "install":
		if len(args) != 2 {
			return errors.New("a JSON profile file is required")
		}
		f, e := os.Open(args[1])
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(f, 32769))
		f.Close()
		if e != nil {
			return e
		}
		p, e := provider.Decode(b)
		if e != nil {
			return e
		}
		if _, ok := provider.Builtins()[p.Name]; ok {
			return errors.New("built-in providers cannot be replaced; choose a distinct name")
		}
		b, e = json.MarshalIndent(p, "", "  ")
		if e != nil {
			return e
		}
		path := filepath.Join(filepath.Dir(o.Config), "providers", p.Name+".json")
		if e = device.SavePrivate(path, b); e != nil {
			return e
		}
		fmt.Fprintf(os.Stderr, "Installed %s · profile SHA-256 %s\n", p.Label, p.Hash())
		return nil
	default:
		return errors.New("unknown provider command")
	}
}
func loadVault(o vaultOptions) (*device.Client, error) {
	c, e := device.Load(o.Config)
	if e != nil {
		return nil, e
	}
	if c.OwnerID == "" {
		return nil, errors.New("device pairing is not complete")
	}
	return device.New(c), nil
}
func requestSpec(o vaultOptions, kind, name, typ string, payload []byte) vaultwire.Request {
	reason := o.Reason
	if reason == "" {
		reason = "Use " + typ + " identity for " + kind + " on this device"
	}
	return vaultwire.Request{AgentID: o.Agent, Session: o.Session, Reason: reason, Kind: kind, Identity: name, IdentityType: typ, Payload: payload, Duration: int64(o.Duration / time.Second)}
}
func waitVault(ctx context.Context, c *device.Client, o vaultOptions, q vaultwire.Request) (device.Pending, vaultwire.RequestState, error) {
	p, e := c.Submit(ctx, q)
	if e != nil {
		return p, vaultwire.RequestState{}, e
	}
	wait, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	state, e := c.Wait(wait, p, os.Stderr)
	if e != nil {
		c.CloseRequest(p.Request.ID)
	}
	return p, state, e
}
func identityType(p provider.Profile) string {
	if _, ok := provider.Builtins()[p.Name]; ok {
		return p.Name
	}
	return "credentials"
}
func wrapVault(ctx context.Context, o vaultOptions, name string, args []string) error {
	p, e := loadProfile(o, name)
	if e != nil {
		return e
	}
	if p.CLI == nil {
		return errors.New("provider has no CLI integration; use autofill")
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	if o.Agent != "" && o.Agent != c.Config.Device.ID {
		return errors.New("command wrappers release credentials only to the calling device")
	}
	inv := vaultwire.Invocation{Provider: p.Name, ProfileHash: p.Hash(), Command: p.CLI.Executable, Arguments: args, Mode: "command"}
	payload, _ := json.Marshal(inv)
	q := requestSpec(o, "credentials", o.Identity, identityType(p), payload)
	q.Network = p.Name
	pending, state, e := waitVault(ctx, c, o, q)
	if e != nil {
		return e
	}
	defer c.CloseRequest(pending.Request.ID)
	grant, e := c.Approval(pending, state)
	if e != nil {
		return e
	}
	defer clear(grant.Secret)
	credentials, e := provider.DecodeCredentials(grant.Secret)
	if e != nil {
		return e
	}
	if e = p.ValidateCredentials(credentials); e != nil {
		return e
	}
	run, cancel := context.WithDeadline(ctx, grant.ExpiresAt)
	defer cancel()
	go c.Watch(run, pending.Request.ID, cancel)
	return provider.Run(run, p, credentials, args, os.Stdin, os.Stdout, os.Stderr)
}
func importVault(ctx context.Context, o vaultOptions, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vault import PROVIDER --name NAME [--stdin | --profile PROFILE | --registry HOST]")
	}
	if args[0] == "chrome" || args[0] == "safari" {
		return importBrowserVault(ctx, o, args[0], args[1:])
	}
	name := provider.Alias(args[0])
	f := flags("import")
	identityName := f.String("name", o.Identity, "new identity name (required)")
	stdin := f.Bool("stdin", false, "read credential JSON from stdin instead of existing configuration")
	profile := f.String("profile", "", "AWS profile to import")
	registry := f.String("registry", "", "Docker registry to import")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if *identityName == "" {
		return errors.New("--name or --identity is required for import")
	}
	p, e := loadProfile(o, name)
	if e != nil {
		return e
	}
	client, e := loadVault(o)
	if e != nil {
		return e
	}
	var credentials provider.Credentials
	if *stdin {
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 1024*1024+1))
		if e != nil {
			return e
		}
		defer clear(b)
		credentials, e = provider.DecodeCredentials(b)
		if e != nil {
			return e
		}
	} else {
		credentials, e = provider.ImportExisting(ctx, name, *profile, *registry)
		if e != nil {
			return e
		}
	}
	if e = p.ValidateCredentials(credentials); e != nil {
		return e
	}
	secret, _ := json.Marshal(credentials)
	defer clear(secret)
	record, e := identity.Import(*identityName, identityType(p), name, secret, nil)
	if e != nil {
		return e
	}
	defer clear(record.Secret)
	plain, _ := json.Marshal(record)
	defer clear(plain)
	// The owner encryption key is pinned during out-of-band device pairing.
	box, e := vaultwire.Seal(client.Config.OwnerBoxPublic, "import:"+client.Config.Device.ID, plain)
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(box)
	q := requestSpec(o, "import", *identityName, record.Type, payload)
	q.Network = name
	pending, state, e := waitVault(ctx, client, o, q)
	if e != nil {
		return e
	}
	defer client.CloseRequest(pending.Request.ID)
	_, e = client.Response(pending, state)
	if e != nil {
		return e
	}
	fmt.Fprintln(os.Stderr, "Credential import approved and saved in the encrypted vault.")
	return nil
}
func identityVault(ctx context.Context, o vaultOptions, args []string) error {
	f := flags("identity")
	kind := f.String("type", "", "identity type")
	network := f.String("network", "mainnet", "Bitcoin network")
	if len(args) == 0 {
		return errors.New("usage: vault identity list | create --type TYPE")
	}
	action := args[0]
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	requestKind := "lookup"
	if action == "create" {
		requestKind = "create"
		if o.Identity == "" || *kind == "" {
			return errors.New("--identity and --type are required to create an identity")
		}
	} else if action != "list" && action != "lookup" {
		return errors.New("unknown identity command")
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	if requestKind == "lookup" {
		records, e := c.Catalog(ctx)
		if e != nil {
			return e
		}
		out := []identity.Record{}
		for _, r := range records {
			if (o.Identity == "" || r.Name == o.Identity) && (*kind == "" || r.Type == *kind) {
				out = append(out, r)
			}
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	q := requestSpec(o, requestKind, o.Identity, *kind, nil)
	q.Network = *network
	p, state, e := waitVault(ctx, c, o, q)
	if e != nil {
		return e
	}
	defer c.CloseRequest(p.Request.ID)
	result, e := c.Response(p, state)
	if e != nil {
		return e
	}
	if !json.Valid(result) {
		return errors.New("invalid public identity response")
	}
	_, e = fmt.Fprintln(os.Stdout, string(result))
	return e
}
