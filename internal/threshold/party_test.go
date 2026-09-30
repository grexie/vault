package threshold

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/vaultwire"
)

type secrets struct{ sign, box []byte }

func fixturePolicy(n int, kind string) (Policy, map[string]secrets) {
	p := Policy{Kind: kind, Epoch: hex.EncodeToString(randomBytes(32))}
	keys := map[string]secrets{}
	for i := 0; i < n; i++ {
		sign, _ := vaultwire.NewKey()
		box, _ := vaultwire.NewKey()
		id := vaultwire.ID(sign.PublicKey().Bytes())
		p.Owners = append(p.Owners, Owner{ID: id, SigningKey: sign.PublicKey().Bytes(), BoxKey: box.PublicKey().Bytes()})
		keys[id] = secrets{sign.Bytes(), box.Bytes()}
	}
	SortOwners(p.Owners)
	return p, keys
}
func randomBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
func approvalsFor(p Policy, keys map[string]secrets, consent Consent) map[string]vaultwire.Signed {
	out := map[string]vaultwire.Signed{}
	for _, o := range p.Owners {
		out[o.ID], _ = vaultwire.Sign(keys[o.ID].sign, "threshold-consent", consent)
	}
	return out
}
func runProtocol(t *testing.T, p Policy, keys map[string]secrets, shares map[string]*Share, digest []byte) (map[string]*Share, []byte) {
	t.Helper()
	mode := "create"
	if shares != nil {
		mode = "sign"
	}
	consent := Consent{PolicyID: p.ID(), SessionID: hex.EncodeToString(randomBytes(32)), Mode: mode, Digest: digest, ExpiresAt: time.Now().Add(10 * time.Minute).UTC()}
	approvals := approvalsFor(p, keys, consent)
	parties := map[string]*Party{}
	for _, o := range p.Owners {
		k := keys[o.ID]
		party, e := Start(p, o.ID, k.sign, k.box, consent, approvals, shares[o.ID])
		if e != nil {
			t.Fatal(e)
		}
		parties[o.ID] = party
		defer party.Close()
	}
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		progressed := false
		for _, source := range parties {
			packets, e := source.Drain()
			if e != nil {
				t.Fatal(e)
			}
			for _, packet := range packets {
				progressed = true
				if e = parties[packet.To].Accept(packet); e != nil {
					t.Fatal(e)
				}
			}
		}
		results := map[string]*Share{}
		var signature []byte
		complete := true
		for id, p := range parties {
			s, sig, e := p.Result()
			if e != nil {
				complete = false
				continue
			}
			results[id] = s
			if len(sig) > 0 {
				signature = sig
			}
		}
		if complete {
			return results, signature
		}
		if !progressed {
			time.Sleep(time.Millisecond)
		}
	}
	t.Fatal("protocol did not finish")
	return nil, nil
}
func TestAllOwnersTaproot(t *testing.T) {
	policy, keys := fixturePolicy(3, "bitcoin")
	shares, _ := runProtocol(t, policy, keys, nil, nil)
	var pub []byte
	for id, s := range shares {
		if s.OwnerID != id || len(s.Data) == 0 {
			t.Fatal("missing independent share")
		}
		if pub == nil {
			pub = s.PublicKey
		} else if hex.EncodeToString(pub) != hex.EncodeToString(s.PublicKey) {
			t.Fatal("inconsistent group public key")
		}
	}
	digest := randomBytes(32)
	_, signature := runProtocol(t, policy, keys, shares, digest)
	pk, e := schnorr.ParsePubKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	sig, e := schnorr.ParseSignature(signature)
	if e != nil || !sig.Verify(digest, pk) {
		t.Fatal("threshold signature rejected", e)
	}
	consent := Consent{PolicyID: policy.ID(), SessionID: hex.EncodeToString(randomBytes(32)), Mode: "sign", Digest: digest, ExpiresAt: time.Now().Add(time.Minute)}
	approvals := approvalsFor(policy, keys, consent)
	delete(approvals, policy.Owners[2].ID)
	self := policy.Owners[0].ID
	k := keys[self]
	if _, e = Start(policy, self, k.sign, k.box, consent, approvals, shares[self]); e == nil {
		t.Fatal("subquorum signing accepted")
	}
	approvals = approvalsFor(policy, keys, consent)
	tampered := consent
	tampered.Digest = randomBytes(32)
	approvals[policy.Owners[1].ID], _ = vaultwire.Sign(keys[policy.Owners[1].ID].sign, "threshold-consent", tampered)
	if _, e = Start(policy, self, k.sign, k.box, consent, approvals, shares[self]); e == nil {
		t.Fatal("different transaction approvals accepted")
	}
}
func TestAllOwnersEthereum(t *testing.T) {
	if testing.Short() {
		t.Skip("CMP distributed generation uses large primes")
	}
	policy, keys := fixturePolicy(2, "ethereum")
	shares, _ := runProtocol(t, policy, keys, nil, nil)
	digest := randomBytes(32)
	_, signature := runProtocol(t, policy, keys, shares, digest)
	pub, e := crypto.DecompressPubkey(shares[policy.Owners[0].ID].PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	recovered, e := crypto.SigToPub(digest, signature)
	if e != nil || crypto.PubkeyToAddress(*pub) != crypto.PubkeyToAddress(*recovered) {
		t.Fatal("threshold Ethereum signature rejected", e)
	}
}
