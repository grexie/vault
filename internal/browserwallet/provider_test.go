//go:build unix

package browserwallet

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/vaultwire"
	"github.com/grexie/vault/internal/walletsign"
)

type testBackend struct {
	mu                   sync.Mutex
	key                  *ecdsa.PrivateKey
	catalog              device.PublicCatalog
	controls, signatures int
	reject               bool
	afterSign            func()
	last                 walletsign.Payload
}

func (b *testBackend) DeviceID() string { return "fixture-device" }
func (b *testBackend) Catalog(context.Context) (device.PublicCatalog, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.catalog, nil
}
func (b *testBackend) Control(_ context.Context, c vaultwire.WalletControl) (vaultwire.WalletControlResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.controls++
	if b.reject {
		return vaultwire.WalletControlResult{}, errors.New("rejected")
	}
	r := b.catalog.Identities[0]
	chains := []string{c.Chain.ChainID}
	for _, p := range b.catalog.WalletPermissions {
		if p.Origin == c.Origin {
			chains = append(chains, p.Chains...)
		}
	}
	p := vaultwire.WalletPermission{ID: device.RandomID(), DeviceID: b.DeviceID(), Origin: c.Origin, IdentityID: r.ID, Identity: r.Name, Address: r.Address, PublicKey: r.PublicKey, Chains: chains, CreatedAt: time.Now(), LastUsedAt: time.Now()}
	remaining := []vaultwire.WalletPermission{}
	for _, v := range b.catalog.WalletPermissions {
		if v.Origin != c.Origin {
			remaining = append(remaining, v)
		}
	}
	b.catalog.WalletPermissions = append(remaining, p)
	return vaultwire.WalletControlResult{Permission: p, Control: c}, nil
}
func (b *testBackend) Sign(_ context.Context, p walletsign.Payload) ([]byte, error) {
	b.signatures++
	b.last = p
	if b.reject {
		return nil, errors.New("rejected")
	}
	raw, _ := json.Marshal(p)
	sig, e := walletsign.Sign(b.key, raw)
	if b.afterSign != nil {
		b.afterSign()
	}
	return sig, e
}
func fixtureBridge(t *testing.T) (*Bridge, *testBackend) {
	t.Helper()
	key, e := crypto.GenerateKey()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { key.D.SetInt64(0) })
	r := identity.Record{ID: "fixture-ethereum", Name: "Fixture Ethereum", Type: "ethereum", Address: crypto.PubkeyToAddress(key.PublicKey).Hex(), PublicKey: hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))}
	back := &testBackend{key: key, catalog: device.PublicCatalog{Identities: []identity.Record{r}}}
	return New(back, Store{filepath.Join(t.TempDir(), "wallet.json")}), back
}
func invoke(b *Bridge, origin, method string, params any) (any, error) {
	raw, _ := json.Marshal(params)
	return b.Call(context.Background(), origin, method, raw)
}
func TestOriginPermissionsAndRevocation(t *testing.T) {
	b, back := fixtureBridge(t)
	a, z := "https://a.example", "https://b.example"
	got, e := invoke(b, a, "eth_accounts", []any{})
	if e != nil || len(got.([]string)) != 0 || back.controls != 0 {
		t.Fatal("address leaked before connection", e)
	}
	back.reject = true
	if _, e = invoke(b, a, "eth_requestAccounts", []any{}); e == nil {
		t.Fatal("denial ignored")
	}
	back.reject = false
	if _, e = invoke(b, a, "eth_requestAccounts", []any{}); e != nil {
		t.Fatal(e)
	}
	got, e = invoke(b, z, "eth_accounts", []any{})
	if e != nil || len(got.([]string)) != 0 {
		t.Fatal("cross-origin address disclosure")
	}
	if _, e = invoke(b, z, "personal_sign", []any{"0x00", back.catalog.Identities[0].Address}); e == nil || back.signatures != 0 {
		t.Fatal("unconnected site signed")
	}
	if _, e = invoke(b, a+"/path", "eth_accounts", []any{}); e == nil {
		t.Fatal("non-origin accepted")
	}
	if _, e = invoke(b, a, "wallet_revokePermissions", []any{map[string]any{"eth_accounts": map[string]any{}}}); e != nil {
		t.Fatal(e)
	}
	got, e = invoke(b, a, "eth_accounts", []any{})
	if e != nil || len(got.([]string)) != 0 {
		t.Fatal("local revocation ignored")
	}
	if _, e = invoke(b, a, "eth_requestAccounts", []any{}); e != nil {
		t.Fatal(e)
	}
	back.catalog.WalletPermissions = nil
	got, e = invoke(b, a, "eth_accounts", []any{})
	if e != nil || len(got.([]string)) != 0 {
		t.Fatal("PWA revocation ignored")
	}
}
func TestMessagesAndPermissionChangeDuringApproval(t *testing.T) {
	b, back := fixtureBridge(t)
	origin := "https://a.example"
	if _, e := invoke(b, origin, "eth_requestAccounts", []any{}); e != nil {
		t.Fatal(e)
	}
	address := back.catalog.Identities[0].Address
	result, e := invoke(b, origin, "personal_sign", []any{"0x68656c6c6f", address})
	if e != nil {
		t.Fatal(e)
	}
	sig, _ := hex.DecodeString(result.(string)[2:])
	raw, _ := json.Marshal(back.last)
	if e = walletsign.Verify(raw, sig, back.catalog.Identities[0].PublicKey); e != nil {
		t.Fatal(e)
	}
	if back.last.Origin != origin || back.last.Submit {
		t.Fatal("wrong approval scope")
	}
	back.afterSign = func() { back.catalog.WalletPermissions = nil }
	if _, e = invoke(b, origin, "personal_sign", []any{"0x00", address}); e == nil {
		t.Fatal("signature returned after website revocation")
	}
}
func TestChainsNormalizationAndExactBroadcast(t *testing.T) {
	b, back := fixtureBridge(t)
	origin := "https://a.example"
	broadcasts := 0
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Method string
			Params []json.RawMessage
		}
		json.NewDecoder(r.Body).Decode(&q)
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x7a69"
		case "eth_getTransactionCount":
			result = "0x2"
		case "eth_estimateGas":
			result = "0x186a0"
		case "eth_gasPrice", "eth_maxPriorityFeePerGas":
			result = "0x1"
		case "eth_getBlockByNumber":
			result = map[string]string{"baseFeePerGas": "0x1"}
		case "eth_sendRawTransaction":
			broadcasts++
			var encoded string
			json.Unmarshal(q.Params[0], &encoded)
			raw, _ := hex.DecodeString(encoded[2:])
			var tx types.Transaction
			if e := tx.UnmarshalBinary(raw); e != nil {
				t.Error(e)
			}
			result = tx.Hash().Hex()
		default:
			t.Errorf("unexpected upstream method %s", q.Method)
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	defer node.Close()
	_, e := invoke(b, origin, "eth_requestAccounts", []any{})
	if e != nil {
		t.Fatal(e)
	}
	chain := vaultwire.WalletChain{ChainID: "0x7a69", Name: "Local fixture", Currency: vaultwire.WalletCurrency{Name: "ETH", Symbol: "ETH", Decimals: 18}, RPCURLs: []string{node.URL}}
	if _, e = invoke(b, origin, "wallet_addEthereumChain", []any{chain}); e != nil {
		t.Fatal(e)
	}
	if _, e = invoke(b, origin, "wallet_switchEthereumChain", []any{map[string]string{"chainId": "0x7a69"}}); e != nil {
		t.Fatal(e)
	}
	for _, method := range []string{"eth_signTransaction", "eth_sendTransaction"} {
		for _, data := range []string{"0x", "0xa9059cbb" + strings.Repeat("0", 63) + "1" + strings.Repeat("0", 62) + "64", "0x095ea7b3" + strings.Repeat("0", 63) + "1" + strings.Repeat("f", 64), "0x12345678"} {
			tx := map[string]any{"from": back.catalog.Identities[0].Address, "to": "0x0000000000000000000000000000000000000001", "value": "0x0", "data": data}
			if _, e = invoke(b, origin, method, []any{tx}); e != nil {
				t.Fatal(method, e)
			}
			if back.last.RPCURL != node.URL || back.last.ChainID != "0x7a69" || back.last.Submit != (method == "eth_sendTransaction") {
				t.Fatal("endpoint or broadcast consent not bound")
			}
		}
	}
	if broadcasts != 4 {
		t.Fatal("sign-only broadcast or missing submission", broadcasts)
	}
	changed := chain
	changed.RPCURLs = []string{"https://attacker.example"}
	if _, e = invoke(b, origin, "wallet_addEthereumChain", []any{changed}); e != nil {
		t.Fatal(e)
	}
	saved, _ := b.Store.chain(chain.ChainID)
	if saved.RPCURLs[0] != node.URL {
		t.Fatal("site replaced global RPC endpoint")
	}
	if _, e = invoke(b, origin, "wallet_switchEthereumChain", []any{map[string]string{"chainId": "0x12345"}}); e == nil {
		t.Fatal("unknown chain switched")
	}
	if _, e = invoke(b, origin, "eth_sendRawTransaction", []any{"0x00"}); e == nil {
		t.Fatal("unapproved raw broadcast allowed")
	}
}
func TestPublicRPCRanges(t *testing.T) {
	for _, s := range []string{"100.100.100.100", "100.64.0.1", "10.0.0.1", "127.0.0.1", "169.254.169.254", "::1", "fc00::1", "::ffff:100.64.0.1", "64:ff9b::a00:1", "2002:0a00:0001::1", "192.0.2.1"} {
		if publicRPCIP(net.ParseIP(s)) {
			t.Fatal("private/special address accepted", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicRPCIP(net.ParseIP(s)) {
			t.Fatal("public address rejected", s)
		}
	}
}
func TestNativeFramingBounds(t *testing.T) {
	b, _ := fixtureBridge(t)
	for _, raw := range [][]byte{{0, 0, 0, 0}, {0xff, 0xff, 0xff, 0xff}, append([]byte{2, 0, 0, 0}, '{')} {
		if e := Serve(context.Background(), b, bytes.NewReader(raw), new(bytes.Buffer)); e == nil {
			t.Fatal("invalid native framing accepted")
		}
	}
	payload := []byte(`{"id":"one","origin":"https://example.com","method":"eth_chainId","params":[]}`)
	var in bytes.Buffer
	binary.Write(&in, binary.LittleEndian, uint32(len(payload)))
	in.Write(payload)
	var out bytes.Buffer
	if e := Serve(context.Background(), b, &in, &out); e != nil {
		t.Fatal(e)
	}
	if out.Len() < 5 {
		t.Fatal("missing native response")
	}
}
