package hyperliquid

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

type fixture struct {
	Name, Network, SignerAddress, Digest, ActionHash, Msgpack string
	Input                                                     json.RawMessage
	Signature                                                 Signature
}

func fixtures(t *testing.T) (string, []fixture) {
	t.Helper()
	b, e := os.ReadFile("testdata/official-sdk-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		TestPrivateKey string
		Vectors        []fixture
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	if len(f.Vectors) != 164 {
		t.Fatal("SDK vectors missing")
	}
	return f.TestPrivateKey, f.Vectors
}
func TestOfficialSDKVectors(t *testing.T) {
	keyHex, vectors := fixtures(t)
	key, e := crypto.HexToECDSA(strings.TrimPrefix(keyHex, "0x"))
	if e != nil {
		t.Fatal(e)
	}
	defer key.D.SetInt64(0)
	pub := hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			raw, e := Prepare(v.Input, v.Network, v.SignerAddress)
			if e != nil {
				t.Fatal(e)
			}
			q, e := Decode(raw)
			if e != nil {
				t.Fatal(e)
			}
			if got := "0x" + hex.EncodeToString(q.Digest()); got != v.Digest {
				t.Fatalf("digest %s want %s", got, v.Digest)
			}
			if v.ActionHash != "" && "0x"+hex.EncodeToString(q.ActionHash()) != v.ActionHash {
				t.Fatal("action hash mismatch")
			}
			signed, e := Sign(key, raw)
			if e != nil {
				t.Fatal(e)
			}
			var out ExchangeRequest
			if json.Unmarshal(signed, &out) != nil {
				t.Fatal("bad result")
			}
			for _, pair := range [][2]string{{out.Signature.R, v.Signature.R}, {out.Signature.S, v.Signature.S}} {
				a, _ := new(big.Int).SetString(pair[0][2:], 16)
				b, _ := new(big.Int).SetString(pair[1][2:], 16)
				if a.Cmp(b) != 0 {
					t.Fatal("SDK signature scalar mismatch")
				}
			}
			if out.Signature.V != v.Signature.V {
				t.Fatal("SDK recovery ID mismatch")
			}
			if e = Verify(raw, signed, pub); e != nil {
				t.Fatal(e)
			}
			review, e := Review(raw)
			if e != nil || review.Digest != v.Digest || len(review.Fields) < 5 || len(review.Warnings) == 0 {
				t.Fatal("missing review", e)
			}
			// Every changed signed input must invalidate the original result.
			for _, edit := range []func(*Request){func(q *Request) { q.Nonce++ }, func(q *Request) {
				if q.Network == "mainnet" {
					q.Network = "testnet"
				} else {
					q.Network = "mainnet"
				}
			}, func(q *Request) { q.Signer = "0x0000000000000000000000000000000000000001" }, func(q *Request) { q.Action = []byte(`{"type":"noop"}`) }, func(q *Request) { s := "0x0000000000000000000000000000000000000002"; q.VaultAddress = &s }, func(q *Request) { n := uint64(1); q.ExpiresAfter = &n }} {
				changed := q
				edit(&changed)
				b, _ := json.Marshal(changed)
				if bytes.Equal(b, raw) {
					continue
				}
				if e := Verify(b, signed, pub); e == nil {
					t.Fatal("changed payload accepted")
				}
			}
		})
	}
}
func TestRejectAmbiguousOrUnsupportedActions(t *testing.T) {
	const signer = "0x14791697260E4c9A71f18484C9f997B308e59325"
	for _, raw := range []string{
		`{"action":{"type":"noop","type":"noop"},"nonce":1}`, `{"action":{"type":"noop","Type":"noop"},"nonce":1}`,
		`{"action":{"type":"noop","other":true},"nonce":1}`, `{"action":{"type":"noop"},"nonce":1,"signature":{}}`,
		`{"action":{"type":"noop"},"nonce":1.0}`, `{"action":{"type":"noop"},"nonce":1e3}`, `{"action":{"type":"noop"},"nonce":-1}`,
		`{"action":{"type":"noop"},"nonce":18446744073709551616}`, `{"action":{"type":"noop"},"nonce":1} {}`,
		`{"action":{"type":"eth_signTypedData"},"nonce":1}`, `{"action":{"type":"cancel","cancels":[],"f":false},"nonce":1}`,
		`{"action":{"type":"approveAgent","agentAddress":"0x0000000000000000000000000000000000000002","nonce":2},"nonce":1}`,
		`{"action":{"type":"usdSend","destination":"0x0000000000000000000000000000000000000002","amount":"1 subaccount:0x00","time":1},"nonce":1}`,
		`{"action":{"type":"usdSend","destination":"0x0000000000000000000000000000000000000002","amount":"1","time":1},"nonce":1,"expiresAfter":2}`,
		`{"action":{"type":"usdSend","destination":"0x0000000000000000000000000000000000000002","amount":"1","time":1},"nonce":1,"vaultAddress":"0x0000000000000000000000000000000000000003"}`,
		`{"action":{"type":"approveAgent","agentAddress":"0x0000000000000000000000000000000000000002","agentName":"safe\u202eevil","nonce":1},"nonce":1}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, e := Prepare([]byte(raw), "testnet", signer); e == nil {
				t.Fatal("accepted invalid action")
			}
		})
	}
	_, vectors := fixtures(t)
	for _, v := range vectors {
		if !strings.Contains(v.Name, "order-trigger") {
			continue
		}
		for _, needle := range []string{`"triggerPx":`, `"builder":`, `"isMarket":`} {
			if !bytes.Contains(v.Input, []byte(needle)) {
				continue
			}
			bad := bytes.Replace(v.Input, []byte(needle), []byte(needle+`null,`+needle), 1)
			if _, e := Prepare(bad, v.Network, signer); e == nil {
				t.Fatal("nested duplicate accepted")
			}
		}
		break
	}
}
func FuzzDecodeAndReview(f *testing.F) {
	f.Add([]byte(`{"network":"testnet","signer":"0x0000000000000000000000000000000000000001","action":{"type":"noop"},"nonce":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		q, e := Decode(b)
		if e != nil {
			return
		}
		q.Digest()
		if _, e := Review(b); e != nil {
			t.Fatal(e)
		}
	})
}
