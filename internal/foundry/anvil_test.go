package foundry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestVanillaCastAndForge(t *testing.T) {
	bin := os.Getenv("VAULT_FOUNDRY_BIN")
	if bin == "" {
		t.Skip("set VAULT_FOUNDRY_BIN to run real Foundry/Anvil integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	var log bytes.Buffer
	anvil := exec.CommandContext(ctx, filepath.Join(bin, "anvil"), "--host", "127.0.0.1", "--port", fmt.Sprint(port), "--chain-id", "31337", "--silent")
	anvil.Stdout = &log
	anvil.Stderr = &log
	if err = anvil.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { anvil.Process.Kill(); anvil.Wait() }()
	upstream := fmt.Sprintf("http://127.0.0.1:%d", port)
	for i := 0; i < 100; i++ {
		r, e := http.Post(upstream, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`))
		if e == nil {
			r.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
		if i == 99 {
			t.Fatal("Anvil did not start")
		}
	}
	key, _ := crypto.GenerateKey()
	defer key.D.SetInt64(0)
	address := crypto.PubkeyToAddress(key.PublicKey)
	// Test funds are created only on the loopback Anvil chain.
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "anvil_setBalance", "params": []any{address, "0x3635c9adc5dea00000"}})
	r, e := http.Post(upstream, "application/json", bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	fixture := &fixtureSigner{key: key}
	a, e := New(ctx, Config{Upstream: upstream, Address: address, ChainID: big.NewInt(31337), Broadcast: true}, fixture)
	if e != nil {
		t.Fatal(e)
	}
	endpoint, e := a.Start()
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	run := func(tool string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(bin, tool), args...)
		cmd.Env = append(os.Environ(), "ETH_RPC_URL="+endpoint, "ETH_FROM="+address.Hex())
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("%s failed: %v\n%s", tool, e, out)
		}
		return string(out)
	}
	run("cast", "send", "0x0000000000000000000000000000000000000001", "--value", "1wei", "--unlocked", "--rpc-url", endpoint, "--from", address.Hex(), "--json")
	run("cast", "send", "0x0000000000000000000000000000000000000001", "--value", "2wei", "--legacy", "--unlocked", "--rpc-url", endpoint, "--from", address.Hex(), "--json")
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "src"), 0700)
	os.WriteFile(filepath.Join(dir, "src", "Counter.sol"), []byte("// SPDX-License-Identifier: MIT\npragma solidity =0.8.30; contract Counter { uint256 public value; function set(uint256 v) external { value=v; } }"), 0600)
	out := run("forge", "create", "src/Counter.sol:Counter", "--root", dir, "--use", "0.8.30", "--broadcast", "--unlocked", "--rpc-url", endpoint, "--from", address.Hex(), "--json")
	var deployed struct {
		DeployedTo string `json:"deployedTo"`
	}
	start := strings.Index(out, "{")
	if start < 0 || json.Unmarshal([]byte(out[start:]), &deployed) != nil || deployed.DeployedTo == "" {
		t.Fatal("missing Forge deployment receipt", out)
	}
	run("cast", "send", deployed.DeployedTo, "set(uint256)", "42", "--unlocked", "--rpc-url", endpoint, "--from", address.Hex(), "--json")
	got := run("cast", "call", deployed.DeployedTo, "value()(uint256)", "--rpc-url", endpoint)
	if strings.TrimSpace(got) != "42" {
		t.Fatal("wrong onchain fixture value", got)
	}
	if fixture.calls.Load() != 4 {
		t.Fatalf("expected 4 approved signatures, got %d", fixture.calls.Load())
	}
	t.Log("Vanilla Cast legacy/EIP-1559 sends, Forge contract creation and contract call verified on loopback Anvil")
}
