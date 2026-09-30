package foundry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/identity"
)

type fixtureSigner struct {
	key    *ecdsa.PrivateKey
	calls  atomic.Int32
	tamper bool
}

func (s *fixtureSigner) SignEthereum(ctx context.Context, raw []byte) ([]byte, error) {
	s.calls.Add(1)
	if s.tamper {
		var tx map[string]any
		json.Unmarshal(raw, &tx)
		tx["value"] = "0x5"
		raw, _ = json.Marshal(tx)
	}
	return identity.SignEthereum(s.key, raw)
}
func TestRPCBoundary(t *testing.T) {
	key, _ := crypto.GenerateKey()
	signer := &fixtureSigner{key: key}
	address := crypto.PubkeyToAddress(key.PublicKey)
	upstreamCalls := []string{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q request
		json.NewDecoder(r.Body).Decode(&q)
		upstreamCalls = append(upstreamCalls, q.Method)
		var v any = "0x0"
		switch q.Method {
		case "eth_chainId":
			v = "0x7a69"
		case "eth_sendRawTransaction":
			v = "0xaccepted"
		case "eth_estimateGas":
			v = "0x5208"
		case "eth_gasPrice":
			v = "0x1"
		}
		json.NewEncoder(w).Encode(result(q.ID, v))
	}))
	defer upstream.Close()
	a, err := New(context.Background(), Config{Upstream: upstream.URL, Address: address, ChainID: big.NewInt(31337)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := a.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	tx := map[string]any{"from": address.Hex(), "to": "0x0000000000000000000000000000000000000001", "chainId": "0x7a69", "nonce": "0x0", "gas": "0x5208", "gasPrice": "0x1", "value": "0x0"}
	call := func(method string, params any, origin string) response {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		r, _ := http.NewRequest("POST", endpoint, bytes.NewReader(b))
		r.Header.Set("Origin", origin)
		res, e := http.DefaultClient.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		if origin != "" {
			if res.StatusCode != 403 {
				t.Fatal("browser origin accepted")
			}
			return response{}
		}
		var out response
		if e = json.NewDecoder(res.Body).Decode(&out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	signed := call("eth_signTransaction", []any{tx}, "")
	if signed.Error != nil {
		t.Fatal(signed.Error)
	}
	var raw hexutil.Bytes
	if json.Unmarshal(signed.Result, &raw) != nil {
		t.Fatal("signed bytes missing")
	}
	original, _ := json.Marshal(tx)
	if _, err = identity.VerifyEthereum(original, raw); err != nil {
		t.Fatal(err)
	}
	if signer.calls.Load() != 1 {
		t.Fatal("wrong sign count")
	}
	for _, method := range []string{"eth_sendTransaction", "eth_sendRawTransaction", "eth_sign", "personal_unlockAccount", "anvil_setBalance", "admin_addPeer"} {
		if call(method, []any{tx}, "").Error == nil {
			t.Fatal("unsafe method accepted", method)
		}
	}
	call("eth_signTransaction", []any{tx}, "https://attacker.invalid")
	if signer.calls.Load() != 1 {
		t.Fatal("denied calls reached signer")
	}
	for _, method := range upstreamCalls {
		if strings.Contains(method, "send") {
			t.Fatal("sign-only adapter broadcast")
		}
	}
	tx["chainId"] = "0x1"
	if call("eth_signTransaction", []any{tx}, "").Error == nil {
		t.Fatal("wrong chain accepted")
	}
	tx["chainId"] = "0x7a69"
	signer.tamper = true
	if call("eth_signTransaction", []any{tx}, "").Error == nil {
		t.Fatal("substituted response accepted")
	}
	r, _ := http.NewRequest("POST", endpoint, strings.NewReader(`{"jsonrpc":"2.0","method":"eth_signTransaction","params":[]}`))
	res, _ := http.DefaultClient.Do(r)
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatal("notification executed")
	}
}
