//go:build unix

package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/keychain"
	"github.com/grexie/vault/internal/provider"
	"github.com/grexie/vault/internal/vaultwire"
)

func keychainVault(ctx context.Context, o vaultOptions, args []string) error {
	if len(args) != 1 || args[0] != "serve" {
		return errors.New("usage: vault keychain serve")
	}
	client, e := loadVault(o)
	if e != nil {
		return e
	}
	return keychain.Serve(ctx, client.Config)
}
func importBrowserVault(ctx context.Context, o vaultOptions, source string, args []string) error {
	f := flags("import " + source)
	origin := f.String("origin", "", "exact HTTPS website origin (required)")
	username := f.String("username", "", "one account to import")
	profile := f.String("browser-profile", "Default", "Chrome profile name")
	name := f.String("name", o.Identity, "new identity name (required)")
	csvFile := f.String("csv", "", "explicit export file from the browser or Passwords app")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *name == "" {
		return errors.New("an identity name is required")
	}
	intent := keychain.Intent{Source: source, Origin: *origin, Username: *username, Profile: *profile}
	if e := intent.Validate(); e != nil {
		return e
	}
	client, e := loadVault(o)
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(intent)
	q := requestSpec(o, "keychain-import", *name, "login", payload)
	q.AgentID = client.Config.Device.ID
	pending, state, e := waitVault(ctx, client, o, q)
	if e != nil {
		return e
	}
	defer client.CloseRequest(pending.Request.ID)
	if _, e = client.Response(pending, state); e != nil {
		return e
	}
	var credentials provider.Credentials
	if *csvFile != "" {
		file, e := os.Open(*csvFile)
		if e != nil {
			return errors.New("cannot open the selected browser export")
		}
		credentials, e = keychain.FromCSV(file, intent)
		file.Close()
		if e != nil {
			return e
		}
	} else {
		credentials, e = keychain.Import(ctx, client.Config, keychain.ImportPermit{Request: pending.Signed, Response: *state.Response})
		if e != nil {
			return e
		}
	}
	raw, _ := json.Marshal(credentials)
	defer clear(raw)
	record, e := identity.Import(*name, "login", "", raw, nil)
	if e != nil {
		return e
	}
	defer clear(record.Secret)
	plain, _ := json.Marshal(record)
	defer clear(plain)
	box, e := vaultwire.Seal(client.Config.OwnerBoxPublic, "import:"+client.Config.Device.ID, plain)
	if e != nil {
		return e
	}
	cipher, _ := json.Marshal(box)
	fmt.Fprintln(os.Stderr, "Website login read locally. Review the account in Vault to finish saving it.")
	q = requestSpec(o, "import", *name, "login", cipher)
	q.AgentID = client.Config.Device.ID
	next, result, e := waitVault(ctx, client, o, q)
	if e != nil {
		return e
	}
	defer client.CloseRequest(next.Request.ID)
	if _, e = client.Response(next, result); e != nil {
		return e
	}
	fmt.Fprintln(os.Stderr, "Website login imported. The original browser login was preserved.")
	return nil
}
