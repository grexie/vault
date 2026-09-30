package cloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/vaultwire"
)

func (f *securityReviewFixture) seedVault(t *testing.T) VaultRecord {
	t.Helper()
	ctx := context.Background()
	v, err := f.store.Get(ctx, "users", f.user.key(), &f.user)
	if err != nil {
		t.Fatal(err)
	}
	id := random(32)
	f.user.Credentials = []webauthn.Credential{{ID: id}}
	if err = f.store.Put(ctx, "users", f.user.key(), v, f.user, nil); err != nil {
		t.Fatal(err)
	}
	// The broker treats these browser-encrypted values as opaque. This fixture
	// tests lifecycle authorization, not encryption of an actual private key.
	record := VaultRecord{Credential: base64.RawURLEncoding.EncodeToString(id), WrappedKey: Blob{IV: random(12), Ciphertext: random(32)}, Data: Blob{IV: random(12), Ciphertext: random(32)}}
	if err = f.store.Put(ctx, "vaults", f.user.key(), 0, record, nil); err != nil {
		t.Fatal(err)
	}
	return record
}

func (f *securityReviewFixture) putEncryptedVault(t *testing.T, version int64, record VaultRecord, deletions []identityRevocation) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(map[string]any{"version": version, "vault": record, "revokeIdentities": deletions})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPut, "https://vault.example/api/v1/vault", bytes.NewReader(b))
	r.Header.Set("Origin", "https://vault.example")
	r.AddCookie(&http.Cookie{Name: f.s.cookie, Value: f.cookie})
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	return w
}

func (f *securityReviewFixture) identityRequest(t *testing.T, spec vaultwire.Request) device.Pending {
	t.Helper()
	spec.Reason = "Exercise deletion and approval lifecycle isolation"
	spec.Duration = 60
	if spec.Kind == "ssh" {
		spec.Managed = true
		spec.AgentID = f.agent.Config.Device.ID
	}
	p, err := f.requester.Submit(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Managed {
		key, err := vaultwire.NewKey()
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := vaultwire.Sign(f.agent.Config.PrivateKey, "receiver", vaultwire.Receiver{RequestID: p.Request.ID, RequestHash: vaultwire.Digest(p.Signed.Payload), PublicKey: key.PublicKey().Bytes(), ExpiresAt: time.Now().Add(time.Minute)})
		if err != nil {
			t.Fatal(err)
		}
		if err = f.agent.Call(context.Background(), "/api/v1/device/requests/"+p.Request.ID+"/receiver", map[string]any{"receiver": receiver}, nil); err != nil {
			t.Fatal(err)
		}
		p.Receiver = &receiver
	}
	return p
}

func (f *securityReviewFixture) approveVersion(t *testing.T, p device.Pending, version int64) *httptest.ResponseRecorder {
	t.Helper()
	key, err := vaultwire.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	box, err := vaultwire.Seal(key.PublicKey().Bytes(), "fixture", []byte("encrypted lifecycle fixture"))
	if err != nil {
		t.Fatal(err)
	}
	return f.browser(t, "/api/v1/requests/"+p.Request.ID+"/approve", map[string]any{"box": box, "verification": f.verification(t, "approve:"+p.Request.ID), "vaultVersion": version})
}

func (f *securityReviewFixture) completeVersion(t *testing.T, p device.Pending, version int64) *httptest.ResponseRecorder {
	t.Helper()
	response, err := vaultwire.Sign(f.ownerPrivate, "response", vaultwire.Response{RequestID: p.Request.ID, RequestHash: vaultwire.Digest(p.Signed.Payload), Result: []byte(`[]`), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	return f.browser(t, "/api/v1/requests/"+p.Request.ID+"/complete", map[string]any{"response": response, "verification": f.verification(t, "approve:"+p.Request.ID), "vaultVersion": version})
}

func (f *securityReviewFixture) requireState(t *testing.T, p device.Pending, want string) {
	t.Helper()
	var state vaultwire.RequestState
	if _, err := f.store.Get(context.Background(), "requests:"+f.user.key(), p.Request.ID, &state); err != nil {
		t.Fatal(err)
	}
	if state.Status != want {
		t.Fatalf("%s/%s status = %q, want %q", p.Request.IdentityType, p.Request.Identity, state.Status, want)
	}
	if want == "revoked" && (state.Box != nil || state.Authorization != nil || state.Response != nil) {
		t.Fatal("revoked request retained a grant or response")
	}
}

func TestSecurityReviewIdentityDeletionRevokesNamedAndWildcardRequests(t *testing.T) {
	f := newSecurityReviewFixture(t)
	record := f.seedVault(t)
	target := f.identityRequest(t, vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Fixture"})
	wildcard := f.identityRequest(t, vaultwire.Request{Kind: "ssh", IdentityType: "ssh"})
	pending := f.identityRequest(t, vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Fixture"})
	other := f.identityRequest(t, vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Unrelated"})
	otherType := f.identityRequest(t, vaultwire.Request{Kind: "credentials", IdentityType: "github", Identity: "Fixture", Payload: []byte(`{"provider":"github"}`)})
	for _, p := range []device.Pending{target, wildcard, other, otherType} {
		if w := f.approveVersion(t, p, 1); w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := f.putEncryptedVault(t, 1, record, []identityRevocation{{Name: "Fixture", Type: "ssh"}}); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, p := range []device.Pending{target, wildcard, pending} {
		f.requireState(t, p, "revoked")
	}
	for _, p := range []device.Pending{other, otherType} {
		f.requireState(t, p, "approved")
	}
	if w := f.approveVersion(t, pending, 2); w.Code != http.StatusConflict {
		t.Fatal("deleted identity's pending request could be approved", w.Code)
	}
}

func TestSecurityReviewIdentityDeletionRespectsCustomProvider(t *testing.T) {
	f := newSecurityReviewFixture(t)
	record := f.seedVault(t)
	var requests []device.Pending
	for _, item := range []struct{ name, provider string }{{"Fixture", "provider-a"}, {"", "provider-a"}, {"Fixture", "provider-b"}, {"Unrelated", "provider-a"}} {
		payload, _ := json.Marshal(map[string]string{"provider": item.provider})
		p := f.identityRequest(t, vaultwire.Request{Kind: "credentials", IdentityType: "credentials", Identity: item.name, Network: item.provider, Payload: payload})
		requests = append(requests, p)
		if w := f.approveVersion(t, p, 1); w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if w := f.putEncryptedVault(t, 1, record, []identityRevocation{{Name: "Fixture", Type: "credentials", Network: "provider-a"}}); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	for i, p := range requests {
		want := "approved"
		if i < 2 {
			want = "revoked"
		}
		f.requireState(t, p, want)
	}
}

func TestSecurityReviewVaultMutationRejectsStaleApprovalsAndCompletions(t *testing.T) {
	f := newSecurityReviewFixture(t)
	record := f.seedVault(t)
	approval := f.identityRequest(t, vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Unrelated"})
	completion := f.identityRequest(t, vaultwire.Request{Kind: "lookup", IdentityType: "ssh", Identity: "Unrelated"})
	if w := f.putEncryptedVault(t, 1, record, []identityRevocation{{Name: "Deleted", Type: "ssh"}}); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := f.approveVersion(t, approval, 1); w.Code != http.StatusConflict {
		t.Fatal("stale browser approval accepted", w.Code, w.Body.String())
	}
	f.requireState(t, approval, "pending")
	if w := f.completeVersion(t, completion, 1); w.Code != http.StatusConflict {
		t.Fatal("stale browser completion accepted", w.Code, w.Body.String())
	}
	f.requireState(t, completion, "pending")
	if w := f.approveVersion(t, approval, 2); w.Code != http.StatusOK {
		t.Fatal("current browser approval rejected", w.Code, w.Body.String())
	}
	if w := f.completeVersion(t, completion, 2); w.Code != http.StatusOK {
		t.Fatal("current browser completion rejected", w.Code, w.Body.String())
	}
}

func TestSecurityReviewStaleDeletionDoesNotRevokeCurrentAccess(t *testing.T) {
	f := newSecurityReviewFixture(t)
	record := f.seedVault(t)
	p := f.pending(t)
	if w := f.approveVersion(t, p, 1); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := f.putEncryptedVault(t, 0, record, []identityRevocation{{Name: "Fixture", Type: "ssh"}}); w.Code != http.StatusConflict {
		t.Fatal("stale deletion accepted", w.Code, w.Body.String())
	}
	f.requireState(t, p, "approved")
}

type securityReviewFailWrite struct {
	cloudstore.Backend
	mu              sync.Mutex
	lastID, failing string
}

func (b *securityReviewFailWrite) Put(ctx context.Context, doc cloudstore.Document, expected int64) error {
	b.mu.Lock()
	b.lastID = doc.ID
	failed := doc.ID == b.failing
	b.mu.Unlock()
	if failed {
		return errors.New("injected fixture persistence failure")
	}
	return b.Backend.Put(ctx, doc, expected)
}

func (b *securityReviewFailWrite) last() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastID
}

func (b *securityReviewFailWrite) fail(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failing = id
}

func TestSecurityReviewDeletionFailurePreservesEncryptedIdentity(t *testing.T) {
	for _, failVault := range []bool{false, true} {
		t.Run(map[bool]string{false: "revocation write", true: "vault write"}[failVault], func(t *testing.T) {
			backend := &securityReviewFailWrite{Backend: cloudstore.NewMemory()}
			f := newSecurityReviewFixture(t, backend)
			record := f.seedVault(t)
			vaultID := backend.last()
			p := f.pending(t)
			if w := f.approveVersion(t, p, 1); w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body.String())
			}
			if failVault {
				backend.fail(vaultID)
			} else {
				backend.fail(backend.last())
			}
			if w := f.putEncryptedVault(t, 1, record, []identityRevocation{{Name: "Fixture", Type: "ssh"}}); w.Code != http.StatusServiceUnavailable {
				t.Fatal("failed deletion reported success", w.Code, w.Body.String())
			}
			var stored VaultRecord
			version, err := f.store.Get(context.Background(), "vaults", f.user.key(), &stored)
			if err != nil || version != 1 || !bytes.Equal(stored.Data.Ciphertext, record.Data.Ciphertext) {
				t.Fatal("deletion failure lost the encrypted identity", version, err)
			}
			want := "approved"
			if failVault {
				want = "revoked"
			}
			f.requireState(t, p, want)
		})
	}
}

type securityReviewBlockWrite struct {
	cloudstore.Backend
	id                string
	entered, released chan struct{}
	once              sync.Once
}

func (b *securityReviewBlockWrite) Put(ctx context.Context, doc cloudstore.Document, expected int64) error {
	if doc.ID == b.id {
		b.once.Do(func() {
			close(b.entered)
			<-b.released
		})
	}
	return b.Backend.Put(ctx, doc, expected)
}

func TestSecurityReviewDeletionSerializesConcurrentApproval(t *testing.T) {
	backend := &securityReviewBlockWrite{Backend: cloudstore.NewMemory(), entered: make(chan struct{}), released: make(chan struct{})}
	f := newSecurityReviewFixture(t, backend)
	record := f.seedVault(t)
	p := f.identityRequest(t, vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Unrelated"})
	docs, err := f.store.List(context.Background(), "vaults")
	if err != nil || len(docs) != 1 {
		t.Fatal("missing fixture vault", err)
	}
	backend.id = docs[0].ID
	var once sync.Once
	release := func() { once.Do(func() { close(backend.released) }) }
	t.Cleanup(release)
	deleted := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		deleted <- f.putEncryptedVault(t, 1, record, []identityRevocation{{Name: "Deleted", Type: "ssh"}})
	}()
	select {
	case <-backend.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("deletion did not reach its encrypted vault write")
	}
	approved := make(chan *httptest.ResponseRecorder, 1)
	go func() { approved <- f.approveVersion(t, p, 1) }()
	select {
	case w := <-approved:
		t.Fatalf("approval raced an unfinished deletion: %d %s", w.Code, w.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case w := <-deleted:
		if w.Code != http.StatusOK {
			t.Fatal(w.Code, w.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("deletion did not complete")
	}
	select {
	case w := <-approved:
		if w.Code != http.StatusConflict {
			t.Fatal("approval retained the pre-deletion vault version", w.Code, w.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("approval did not resume after deletion")
	}
	f.requireState(t, p, "pending")
}
