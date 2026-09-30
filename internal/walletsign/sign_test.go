package walletsign

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

type vector struct {
	Name, Method, Digest, Signature, Reason string
	Input                                   struct{ Data json.RawMessage }
}

func fixture(t *testing.T) (string, string, []vector, []vector, []vector) {
	t.Helper()
	raw, e := os.ReadFile("testdata/metamask-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		TestPrivateKey, SignerAddress           string
		Vectors, Rejections, CompatibilityCases []vector
	}
	if json.Unmarshal(raw, &f) != nil {
		t.Fatal("invalid fixture")
	}
	return f.TestPrivateKey, f.SignerAddress, f.Vectors, f.Rejections, f.CompatibilityCases
}
func testPayload(v vector, address string) Payload {
	return Payload{Origin: "https://dapp.example", IdentityID: "fixture-id", Identity: "Fixture Ethereum", Address: address, ChainID: "0x1", Method: v.Method, Data: v.Input.Data}
}
func TestIndependentWalletVectors(t *testing.T) {
	k, address, valid, reject, compat := fixture(t)
	key, e := crypto.HexToECDSA(strings.TrimPrefix(k, "0x"))
	if e != nil {
		t.Fatal(e)
	}
	defer key.D.SetInt64(0)
	pub := hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))
	check := func(t *testing.T, v vector, required bool) {
		p := testPayload(v, address)
		raw, _ := json.Marshal(p)
		decoded, e := Decode(raw)
		if e != nil {
			if required {
				t.Fatal(e)
			}
			return
		}
		digest, e := decoded.Digest()
		if e != nil || "0x"+hex.EncodeToString(digest) != v.Digest {
			t.Fatal("digest differs from reference", e)
		}
		signature, e := Sign(key, raw)
		if e != nil || "0x"+hex.EncodeToString(signature) != v.Signature {
			t.Fatal("signature differs from reference", e)
		}
		if e = Verify(raw, signature, pub); e != nil {
			t.Fatal(e)
		}
		review, e := Review(raw)
		if e != nil || review.Digest != v.Digest || len(review.Fields) < 6 {
			t.Fatal("invalid review", e)
		}
	}
	for _, v := range valid {
		t.Run(v.Name, func(t *testing.T) { check(t, v, true) })
	}
	for _, v := range compat {
		t.Run("compat/"+v.Name, func(t *testing.T) { check(t, v, false) })
	}
	for _, v := range reject {
		t.Run("reject/"+v.Name, func(t *testing.T) {
			b, _ := json.Marshal(testPayload(v, address))
			if _, e := Decode(b); e == nil {
				t.Fatal("reference-rejected payload accepted")
			}
		})
	}
}
func TestReviewNeverAuthenticatesExcludedMetadata(t *testing.T) {
	_, a, _, _, cases := fixture(t)
	for _, v := range cases {
		if !strings.Contains(v.Name, "domain-only") && !strings.Contains(v.Name, "unsigned-domain-chain-id") {
			continue
		}
		raw, _ := json.Marshal(testPayload(v, a))
		r, e := Review(raw)
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(strings.Join(r.Warnings, " "), "Unsigned metadata") {
			t.Fatal("unsigned metadata not identified")
		}
		for _, f := range r.Fields {
			if f.Label == "Domain chainId" && strings.Contains(v.Name, "unsigned-domain-chain-id") {
				t.Fatal("unsigned chain displayed as signed")
			}
			if f.Label == "Declared signed fields" && strings.Contains(v.Name, "domain-only") && strings.Contains(f.Value, `"message"`) {
				t.Fatal("unsigned message displayed as signed")
			}
		}
	}
}
func TestSigningEnvelopeRejectsAmbiguity(t *testing.T) {
	_, a, valid, _, _ := fixture(t)
	p := testPayload(valid[0], a)
	raw, _ := json.Marshal(p)
	for _, bad := range [][]byte{[]byte(strings.Replace(string(raw), `"submit":false`, `"submit":false,"Submit":true`, 1)), []byte(strings.Replace(string(raw), `"origin":"https://dapp.example"`, `"origin":"https://dapp.example/path"`, 1)), []byte(strings.Replace(string(raw), `"submit":false`, `"submit":true`, 1)), []byte(strings.Replace(string(raw), `"chainId":"0x1"`, `"chainId":"0x01"`, 1))} {
		if _, e := Decode(bad); e == nil {
			t.Fatal("ambiguous signing envelope accepted")
		}
	}
}
func FuzzWalletReview(f *testing.F) {
	f.Add([]byte(`{"origin":"https://dapp.example","identityId":"fixture","identity":"Fixture","address":"0x0000000000000000000000000000000000000001","chainId":"0x1","method":"personal_sign","data":"0x","submit":false,"rpcUrl":""}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if p, e := Decode(b); e == nil {
			p.Digest()
			if _, e = Review(b); e != nil {
				t.Fatal(e)
			}
		}
	})
}
