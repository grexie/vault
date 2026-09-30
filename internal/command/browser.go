//go:build unix

package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/grexie/vault/internal/autofill"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/provider"
	"github.com/grexie/vault/internal/vaultwire"
)

type fillIntent struct {
	Provider      string   `json:"provider"`
	Origin        string   `json:"origin"`
	DocumentToken string   `json:"documentToken"`
	Fields        []string `json:"fields"`
	Merchant      string   `json:"merchant,omitempty"`
	Amount        string   `json:"amount,omitempty"`
	Currency      string   `json:"currency,omitempty"`
}

func browserVault(ctx context.Context, o vaultOptions, command string, args []string) error {
	f := flags(command)
	browser := f.String("browser", "chrome", "chrome or safari")
	cdp := f.String("cdp", "http://127.0.0.1:9222", "Chrome automation endpoint (literal loopback only)")
	target := f.String("target", "", "browser target ID")
	frame := f.String("frame", "", "Chrome frame ID (default: main frame)")
	kind := f.String("type", "login", "login or payment-card")
	merchant := f.String("merchant", "", "merchant name for a card autofill request")
	amount := f.String("amount", "", "purchase amount, when known; does not authorize submission")
	currency := f.String("currency", "", "ISO currency for the stated amount")
	stdin := f.Bool("stdin", false, "card-cvv: read the device-local CVV from stdin")
	if e := f.Parse(args); e != nil {
		return e
	}
	if command == "card-cvv" {
		if !*stdin || o.Identity == "" {
			return errors.New("usage: vault --identity CARD_NAME card-cvv --stdin (device-local storage only)")
		}
		c, e := device.Load(o.Config)
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(os.Stdin, 8))
		if e != nil {
			return e
		}
		defer clear(b)
		cvv := strings.TrimSpace(string(b))
		if !regexp.MustCompile(`^[0-9]{3,4}$`).MatchString(cvv) {
			return errors.New("CVV must contain 3 or 4 digits")
		}
		plain, _ := json.Marshal(map[string]string{"cvv": cvv})
		defer clear(plain)
		box, e := vaultwire.Seal(c.Device.BoxPublic, "local-cvv:"+o.Identity, plain)
		if e != nil {
			return e
		}
		raw, _ := json.Marshal(box)
		path := cvvPath(o)
		if e = device.SavePrivate(path, raw); e != nil {
			return e
		}
		fmt.Fprintln(os.Stderr, "Saved encrypted CVV on this device only. It is excluded from cloud sync and backups.")
		return nil
	}
	if command == "browser" {
		var targets []autofill.Target
		var e error
		if *browser == "safari" {
			targets, e = autofill.SafariTargets(ctx)
		} else if *browser == "chrome" {
			targets, e = autofill.ChromeTargets(ctx, *cdp)
		} else {
			return errors.New("browser must be chrome or safari")
		}
		if e != nil {
			return e
		}
		for i := range targets {
			targets[i].WebSocket = ""
			u, e := url.Parse(targets[i].URL)
			if e == nil {
				targets[i].URL = u.Scheme + "://" + u.Host
			} else {
				targets[i].URL = ""
			}
		}
		return json.NewEncoder(os.Stdout).Encode(targets)
	}
	if *target == "" || o.Identity == "" || (*kind != "login" && *kind != "payment-card") {
		return errors.New("autofill requires --target and --identity; type must be login or payment-card")
	}
	var b autofill.Browser
	var e error
	if *browser == "chrome" {
		b, e = autofill.OpenChrome(ctx, *cdp, *target, *frame)
	} else if *browser == "safari" {
		b, e = autofill.OpenSafari(*target)
	} else {
		return errors.New("browser must be chrome or safari")
	}
	if e != nil {
		return e
	}
	defer b.Close()
	inspection, e := b.Inspect(ctx)
	if e != nil {
		return e
	}
	if len(inspection.Fields) == 0 {
		return errors.New("no supported visible fields in the selected page")
	}
	if *amount != "" && (!regexp.MustCompile(`^[0-9]{1,10}(\.[0-9]{1,4})?$`).MatchString(*amount) || !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(*currency)) {
		return errors.New("amount must be a positive decimal and currency a three-letter code")
	}
	client, e := loadVault(o)
	if e != nil {
		return e
	}
	intent := fillIntent{*kind, inspection.Origin, inspection.DocumentToken, inspection.Fields, *merchant, *amount, *currency}
	payload, _ := json.Marshal(intent)
	q := requestSpec(o, "autofill", o.Identity, *kind, payload)
	q.Duration = 60
	q.AgentID = client.Config.Device.ID
	pending, state, e := waitVault(ctx, client, o, q)
	if e != nil {
		return e
	}
	defer client.CloseRequest(pending.Request.ID)
	grant, e := client.Approval(pending, state)
	if e != nil {
		return e
	}
	defer clear(grant.Secret)
	credentials, e := provider.DecodeCredentials(grant.Secret)
	if e != nil {
		return e
	}
	if credentials.Provider != *kind {
		return errors.New("approved identity is not an autofill credential")
	}
	values := map[string]string{}
	if *kind == "login" {
		if credentials.Fields["origin"] != inspection.Origin {
			return errors.New("saved login origin does not match the approved website")
		}
		values["username"] = credentials.Fields["username"]
		values["password"] = credentials.Fields["password"]
	} else {
		for _, k := range []string{"cardholder", "number", "expiryMonth", "expiryYear"} {
			values[k] = credentials.Fields[k]
		}
		values["expiry"] = credentials.Fields["expiryMonth"] + "/" + credentials.Fields["expiryYear"]
		if raw, e := os.ReadFile(cvvPath(o)); e == nil {
			var box vaultwire.Envelope
			if json.Unmarshal(raw, &box) != nil {
				return errors.New("invalid local CVV record")
			}
			plain, e := vaultwire.Open(client.Config.BoxPrivate, "local-cvv:"+o.Identity, box)
			if e != nil {
				return errors.New("local CVV could not be decrypted")
			}
			defer clear(plain)
			var data map[string]string
			if json.Unmarshal(plain, &data) != nil {
				return errors.New("invalid local CVV data")
			}
			values["cvv"] = data["cvv"]
		}
	}
	run, cancel := context.WithDeadline(ctx, grant.ExpiresAt)
	defer cancel()
	check, e := client.Status(run, pending.Request.ID)
	if e != nil || check.Status != "approved" || time.Now().After(grant.ExpiresAt) {
		return errors.New("autofill approval is no longer active")
	}
	count, e := b.Fill(run, inspection, values)
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"filled": count, "origin": inspection.Origin, "submitted": false})
}
func cvvPath(o vaultOptions) string {
	return filepath.Join(filepath.Dir(o.Config), "local-cvv", vaultwire.Digest([]byte(o.Identity))+".json")
}
