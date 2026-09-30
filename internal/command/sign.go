//go:build unix

package command

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grexie/vault/internal/foundry"
	"github.com/grexie/vault/internal/identity"
)

type vaultEthereumSigner struct{ options vaultOptions }

func (v vaultEthereumSigner) SignEthereum(ctx context.Context, raw []byte) ([]byte, error) {
	if _, e := identity.ReviewEthereum(raw); e != nil {
		return nil, e
	}
	c, e := loadVault(v.options)
	if e != nil {
		return nil, e
	}
	managedSettings(&v.options, c)
	q := requestSpec(v.options, "ethereum", v.options.Identity, "ethereum", raw)
	q.Duration = 60
	q.AgentID = v.options.Agent
	q.Managed = true
	p, state, e := waitVault(ctx, c, v.options, q)
	if e != nil {
		return nil, e
	}
	defer c.CloseRequest(p.Request.ID)
	signed, e := managedRPC(ctx, c, v.options.AgentURL, p, state, "ethereum", raw)
	if e != nil {
		return nil, e
	}
	if _, e = identity.VerifyEthereum(raw, signed); e != nil {
		return nil, e
	}
	return signed, nil
}
func signVault(ctx context.Context, o vaultOptions, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: vault --identity NAME sign ethereum|bitcoin [--network mainnet] < TRANSACTION")
	}
	kind := args[0]
	f := flags("sign")
	network := f.String("network", "mainnet", "Bitcoin network")
	if e := f.Parse(args[1:]); e != nil {
		return e
	}
	if o.Identity == "" {
		return errors.New("--identity is required for signing")
	}
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 6*1024*1024+1))
	if e != nil || len(raw) > 6*1024*1024 {
		return errors.New("transaction input too large")
	}
	if kind == "ethereum" {
		signed, e := (vaultEthereumSigner{o}).SignEthereum(ctx, raw)
		if e != nil {
			return e
		}
		fmt.Fprintln(os.Stdout, "0x"+hex.EncodeToString(signed))
		return nil
	}
	if kind != "bitcoin" {
		return errors.New("type must be ethereum or bitcoin")
	}
	psbt, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if e != nil {
		return errors.New("Bitcoin input must be a base64 PSBT")
	}
	if _, e = identity.ReviewBitcoin(psbt, *network, nil); e != nil {
		return e
	}
	c, e := loadVault(o)
	if e != nil {
		return e
	}
	managedSettings(&o, c)
	q := requestSpec(o, "bitcoin", o.Identity, "bitcoin", psbt)
	q.Network = *network
	q.Duration = 60
	q.AgentID = o.Agent
	q.Managed = true
	p, state, e := waitVault(ctx, c, o, q)
	if e != nil {
		return e
	}
	defer c.CloseRequest(p.Request.ID)
	signed, e := managedRPC(ctx, c, o.AgentURL, p, state, "bitcoin", psbt)
	if e != nil {
		return e
	}
	fmt.Fprintln(os.Stdout, base64.StdEncoding.EncodeToString(signed))
	return nil
}
func foundryVault(ctx context.Context, o vaultOptions, args []string) error {
	f := flags("foundry")
	rpc := f.String("rpc-url", "", "upstream HTTPS Ethereum RPC, or literal loopback Anvil")
	address := f.String("address", "", "public Ethereum address for this identity")
	chain := f.String("chain-id", "", "explicit decimal chain ID")
	broadcast := f.Bool("broadcast", false, "allow the caller-side adapter to submit signed transactions")
	if e := f.Parse(args); e != nil {
		return e
	}
	id, ok := new(big.Int).SetString(*chain, 10)
	if !ok || id.Sign() <= 0 || !common.IsHexAddress(*address) || o.Identity == "" || f.NArg() == 0 {
		return errors.New("--identity, --rpc-url, --address, --chain-id and a command after -- are required")
	}
	adapter, e := foundry.New(ctx, foundry.Config{Upstream: *rpc, Address: common.HexToAddress(*address), ChainID: id, Broadcast: *broadcast}, vaultEthereumSigner{o})
	if e != nil {
		return e
	}
	defer adapter.Close()
	local, e := adapter.Start()
	if e != nil {
		return e
	}
	command := exec.CommandContext(ctx, f.Arg(0), f.Args()[1:]...)
	env := []string{}
	for _, v := range os.Environ() {
		n, _, _ := strings.Cut(v, "=")
		if n != "ETH_RPC_URL" && n != "ETH_FROM" && n != "ETH_PRIVATE_KEY" && n != "PRIVATE_KEY" {
			env = append(env, v)
		}
	}
	command.Env = append(env, "ETH_RPC_URL="+local, "ETH_FROM="+*address)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}
