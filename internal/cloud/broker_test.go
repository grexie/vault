package cloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/vaultwire"
)

func TestBrokerOwnershipReplayAndEncryptedApproval(t *testing.T) {
	ctx := context.Background()
	backend := cloudstore.NewMemory()
	store, _ := cloudstore.New(backend, random(32))
	s, e := New(ctx, Config{Origin: "https://vault.example"}, store, nil)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(s.Handler())
	defer server.Close()
	ownerKey, _ := vaultwire.NewKey()
	boxKey, _ := vaultwire.NewKey()
	user := User{ID: random(32), Name: "Fixture"}
	store.Put(ctx, "users", user.key(), 0, user, nil)
	session := Session{UserID: user.key(), Wrap: random(32), ExpiresAt: time.Now().Add(time.Hour)}
	cookie := token()
	store.Put(ctx, "sessions", hash(cookie), 0, session, &session.ExpiresAt)
	browserCall := func(path string, input any) *httptest.ResponseRecorder {
		t.Helper()
		raw, _ := json.Marshal(input)
		r := httptest.NewRequest("POST", "https://vault.example"+path, bytes.NewReader(raw))
		r.Header.Set("Origin", "https://vault.example")
		r.AddCookie(&http.Cookie{Name: s.cookie, Value: cookie})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	ticket := func(purpose string) string {
		v := token()
		expires := time.Now().Add(time.Minute)
		store.Put(ctx, "verifications", hash(v), 0, verification{UserID: user.key(), Purpose: purpose}, &expires)
		return v
	}
	cfg, e := device.NewConfig(server.URL, "Fixture device")
	if e != nil {
		t.Fatal(e)
	}
	client := device.New(cfg)
	if _, e = client.Enroll(ctx); e != nil {
		t.Fatal(e)
	}
	pairing := vaultwire.Pairing{DeviceID: cfg.Device.ID, OwnerID: user.key(), OwnerPublic: ownerKey.PublicKey().Bytes(), OwnerBoxPublic: boxKey.PublicKey().Bytes()}
	b, _ := json.Marshal(struct {
		DeviceID       string `json:"deviceId"`
		OwnerID        string `json:"ownerId"`
		OwnerPublic    []byte `json:"ownerPublic"`
		OwnerBoxPublic []byte `json:"ownerBoxPublic"`
	}{pairing.DeviceID, pairing.OwnerID, pairing.OwnerPublic, pairing.OwnerBoxPublic})
	pairing.MAC = vaultwire.PairMAC(cfg.PairingSecret, b)
	plain, _ := json.Marshal(pairing)
	box, _ := vaultwire.Seal(cfg.Device.BoxPublic, "pair:"+cfg.Device.ID, plain)
	input := map[string]any{"deviceId": cfg.Device.ID, "pairingHash": vaultwire.Digest(cfg.PairingSecret), "box": box, "verification": ticket("different-purpose")}
	if browserCall("/api/v1/devices/pair", input).Code != 403 {
		t.Fatal("accepted verification for wrong action")
	}
	input["verification"] = ticket("pair:" + cfg.Device.ID)
	if w := browserCall("/api/v1/devices/pair", input); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if e = client.FinishPair(ctx); e != nil {
		t.Fatal(e)
	}
	// A recorded device HTTP proof is accepted once, then rejected independently
	// of the bearer cookie or TLS session.
	body := []byte(`{}`)
	proof, _ := vaultwire.Sign(cfg.PrivateKey, "http", vaultwire.HTTPProof{DeviceID: cfg.Device.ID, Method: "POST", Path: "/api/v1/device/pairing", BodyHash: vaultwire.Digest(body), Nonce: device.RandomID(), At: time.Now()})
	proofBytes, _ := json.Marshal(proof)
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "https://vault.example/api/v1/device/pairing", bytes.NewReader(body))
		r.Header.Set("X-Vault-Proof", base64.RawURLEncoding.EncodeToString(proofBytes))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		want := 200
		if i == 1 {
			want = 409
		}
		if w.Code != want {
			t.Fatal("replay status", w.Code, want)
		}
	}
	p, e := client.Submit(ctx, vaultwire.Request{Kind: "credentials", Identity: "Fixture", IdentityType: "github", Payload: []byte(`{"provider":"github","mode":"command"}`), Reason: "Exercise an approved fixture command", Duration: 60})
	if e != nil {
		t.Fatal(e)
	}
	var receiver vaultwire.Receiver
	if vaultwire.Verify(cfg.Device.PublicKey, "receiver", *p.Receiver, &receiver) != nil {
		t.Fatal("receiver invalid")
	}
	approval := vaultwire.Approval{RequestID: p.Request.ID, RequestHash: vaultwire.Digest(p.Signed.Payload), ReceiverHash: vaultwire.Digest(p.Receiver.Payload), IdentityID: "fixture-key", IdentityType: "github", Secret: []byte("NEVER-STORE-THIS-IN-PLAINTEXT"), ExpiresAt: time.Now().Add(50 * time.Second)}
	signed, _ := vaultwire.Sign(ownerKey.Bytes(), "approval", approval)
	plain, _ = json.Marshal(signed)
	encrypted, _ := vaultwire.Seal(receiver.PublicKey, "approval:"+p.Request.ID, plain)
	input = map[string]any{"box": encrypted, "verification": ticket("approve:" + p.Request.ID)}
	w := browserCall("/api/v1/requests/"+p.Request.ID+"/approve", input)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if browserCall("/api/v1/requests/"+p.Request.ID+"/approve", input).Code != 409 {
		t.Fatal("approval replay accepted")
	}
	state, e := client.Status(ctx, p.Request.ID)
	if e != nil {
		t.Fatal(e)
	}
	got, e := client.Approval(p, state)
	if e != nil || !bytes.Equal(got.Secret, approval.Secret) {
		t.Fatal("approved secret did not reach the device", e)
	}
	for _, doc := range backend.Docs {
		if bytes.Contains(doc.Payload, approval.Secret) {
			t.Fatal("plaintext reached storage")
		}
	}
	state.Box.Ciphertext[0] ^= 1
	if _, e = client.Approval(p, state); e == nil {
		t.Fatal("tampered envelope accepted")
	}
	otherCfg, _ := device.NewConfig(server.URL, "Another owner")
	other := device.New(otherCfg)
	otherRecord := deviceRecord{Device: otherCfg.Device, OwnerID: "someone-else", CreatedAt: time.Now()}
	store.Put(ctx, "devices", otherCfg.Device.ID, 0, otherRecord, nil)
	if _, e = other.Status(ctx, p.Request.ID); e == nil {
		t.Fatal("cross-owner request access")
	}
	if e = client.Revoke(ctx, p.Request.ID); e != nil {
		t.Fatal(e)
	}
	state, e = client.Status(ctx, p.Request.ID)
	if e != nil || state.Status != "revoked" || state.Box != nil {
		t.Fatal("revocation did not remove encrypted grant", e)
	}
}
