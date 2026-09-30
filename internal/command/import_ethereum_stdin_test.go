//go:build unix

package command

import (
	"os"
	"strings"
	"testing"

	"github.com/grexie/vault/internal/identity"
)

func TestEthereumImportRejectsCharacterDeviceStdin(t *testing.T) {
	// /dev/null is a stable character-device fixture, including without a TTY.
	terminal, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	record, err := readEthereumImport(terminal, "fixture", "")
	if err == nil || !strings.Contains(err.Error(), "pipe the private key") || len(record.Secret) != 0 {
		t.Fatal("character-device stdin was not rejected before reading")
	}
	key, err := identity.Generate("fixture", "ethereum", "")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Secret)
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err = output.Write(key.Secret); err != nil {
		t.Fatal(err)
	}
	output.Close()
	record, err = readEthereumImport(input, "fixture", key.Address)
	if err != nil || record.Address != key.Address {
		t.Fatal("private pipe input was rejected")
	}
	clear(record.Secret)
}
