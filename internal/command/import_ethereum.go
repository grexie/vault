//go:build unix

package command

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/grexie/vault/internal/identity"
)

func importEthereumVault(ctx context.Context, o vaultOptions, args []string) error {
	f := flags("import ethereum")
	// Invalid options must not echo accidentally supplied key material.
	f.SetOutput(io.Discard)
	name := f.String("name", o.Identity, "new identity name (required)")
	stdin := f.Bool("stdin", false, "read a hex private key from stdin (required)")
	address := f.String("address", "", "expected public Ethereum address; reject a different key")
	if e := f.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			f.SetOutput(os.Stderr)
			f.PrintDefaults()
			return nil
		}
		return errors.New("invalid Ethereum import options; use --name NAME --stdin [--address ADDRESS]")
	}
	if !*stdin || *name == "" || f.NArg() != 0 {
		return errors.New("usage: vault import ethereum --name NAME --stdin [--address ADDRESS]; supply the private key only on stdin")
	}
	client, e := loadVault(o)
	if e != nil {
		return e
	}
	record, e := readEthereumImport(os.Stdin, *name, *address)
	if e != nil {
		return e
	}
	defer clear(record.Secret)
	fmt.Fprintln(os.Stderr, "Import Ethereum identity:", record.Name, "·", record.Address)
	return approveIdentityImport(ctx, client, o, record)
}

func readEthereumImport(input io.Reader, name, expectedAddress string) (identity.Record, error) {
	if file, ok := input.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice != 0 {
			return identity.Record{}, errors.New("pipe the private key to stdin; interactive input could expose it in the terminal")
		}
	}
	if expectedAddress != "" && !common.IsHexAddress(expectedAddress) {
		return identity.Record{}, errors.New("--address must be a public Ethereum address")
	}
	raw, e := io.ReadAll(io.LimitReader(input, 1025))
	defer clear(raw)
	if e != nil || len(raw) > 1024 {
		return identity.Record{}, errors.New("could not read Ethereum key; stdin is limited to 1024 bytes")
	}
	record, e := identity.Import(name, "ethereum", "", raw, nil)
	if e != nil {
		return identity.Record{}, e
	}
	if expectedAddress != "" && common.HexToAddress(record.Address) != common.HexToAddress(expectedAddress) {
		clear(record.Secret)
		return identity.Record{}, errors.New("private key does not match the expected Ethereum address")
	}
	return record, nil
}
