//go:build unix

package command

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/hyperliquid"
	"github.com/grexie/vault/internal/identity"
)

func ethereumCatalogIdentity(ctx context.Context, c *device.Client, name string) (identity.Record, error) {
	if name == "" {
		return identity.Record{}, errors.New("--identity is required")
	}
	records, e := c.Catalog(ctx)
	if e != nil {
		return identity.Record{}, e
	}
	matches := []identity.Record{}
	for _, r := range records {
		if r.Name == name && r.Type == "ethereum" {
			matches = append(matches, r)
		}
	}
	if len(matches) != 1 {
		return identity.Record{}, errors.New("expected exactly one Ethereum identity with this name")
	}
	r := matches[0]
	addr, e := hyperliquid.PublicAddress(r.PublicKey)
	if e != nil || !strings.EqualFold(addr, r.Address) {
		return identity.Record{}, errors.New("identity public key does not match its address")
	}
	return r, nil
}

func hyperliquidVault(ctx context.Context, o vaultOptions, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vault --identity NAME hyperliquid balance|positions|orders|review|sign --network mainnet|testnet")
	}
	cmd := args[0]
	if cmd != "balance" && cmd != "positions" && cmd != "orders" && cmd != "review" && cmd != "sign" {
		return errors.New("unknown Hyperliquid command")
	}
	f := flags("hyperliquid " + cmd)
	network := f.String("network", "", "explicit mainnet or testnet")
	address := f.String("address", "", "public account for read/review without an identity")
	dex := f.String("dex", "all", "read all perpetuals venues, native, or a named DEX")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected Hyperliquid arguments; signing/review reads JSON from stdin")
	}
	if *network == "" && (cmd == "balance" || cmd == "positions" || cmd == "orders") {
		*network = "mainnet"
	}
	if *network != "mainnet" && *network != "testnet" {
		return errors.New("--network mainnet or testnet is required")
	}
	if *address != "" && (o.Identity != "" || cmd == "sign") {
		return errors.New("--address is for public reads or offline review; use only --identity for signing")
	}
	var c *device.Client
	var record identity.Record
	if *address == "" {
		var e error
		c, e = loadVault(o)
		if e != nil {
			return e
		}
		record, e = ethereumCatalogIdentity(ctx, c, o.Identity)
		if e != nil {
			return e
		}
		*address = record.Address
	}
	if cmd == "balance" || cmd == "positions" || cmd == "orders" {
		client, e := hyperliquid.NewInfoClient(*network)
		if e != nil {
			return e
		}
		out, e := client.Account(ctx, *network, *address, cmd, *dex)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(out)
	}
	if *dex != "all" {
		return errors.New("--dex applies only to public account reads")
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, hyperliquid.MaxInput+1))
	if e != nil {
		return errors.New("could not read Hyperliquid JSON")
	}
	approved, e := hyperliquid.Prepare(raw, *network, *address)
	if e != nil {
		return e
	}
	if cmd == "review" {
		review, e := hyperliquid.Review(approved)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(review)
	}
	if len(strings.TrimSpace(o.Reason)) < 8 {
		return errors.New("--reason must explain the Hyperliquid signing request (at least 8 characters)")
	}
	if record.Threshold {
		return errors.New("shared Ethereum signing is not supported")
	}
	managedSettings(&o, c)
	q := requestSpec(o, "hyperliquid", o.Identity, "ethereum", approved)
	q.Network = *network
	q.Duration = 60
	q.AgentID = o.Agent
	q.Managed = true
	p, state, e := waitVault(ctx, c, o, q)
	if e != nil {
		return e
	}
	defer c.CloseRequest(p.Request.ID)
	auth, _, e := c.Authorization(p, state)
	if e != nil {
		return e
	}
	if e = hyperliquid.CheckBinding(approved, q.Network, auth.PublicKey); e != nil {
		return e
	}
	signed, e := managedRPC(ctx, c, o.AgentURL, p, state, "hyperliquid", approved)
	if e != nil {
		return e
	}
	if e = hyperliquid.Verify(approved, signed, auth.PublicKey); e != nil {
		return e
	}
	_, e = os.Stdout.Write(append(signed, '\n'))
	return e
}
