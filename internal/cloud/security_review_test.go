package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/vaultwire"
)

type securityReviewFixture struct {
	s                *Server
	store            *cloudstore.Store
	user             User
	cookie           string
	ownerPrivate     []byte
	requester, agent *device.Client
}

func newSecurityReviewFixture(t *testing.T, backends ...cloudstore.Backend) *securityReviewFixture {
	t.Helper()
	ctx := context.Background()
	var backend cloudstore.Backend = cloudstore.NewMemory()
	if len(backends) > 0 {
		backend = backends[0]
	}
	store, err := cloudstore.New(backend, random(32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, Config{Origin: "https://vault.example"}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.Handler())
	t.Cleanup(server.Close)
	f := &securityReviewFixture{s: s, store: store, user: User{ID: random(32), Name: "Security fixture"}, cookie: token()}
	if err = store.Put(ctx, "users", f.user.key(), 0, f.user, nil); err != nil {
		t.Fatal(err)
	}
	session := Session{UserID: f.user.key(), Wrap: random(32), ExpiresAt: time.Now().Add(time.Hour)}
	if err = store.Put(ctx, "sessions", hash(f.cookie), 0, session, &session.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	owner, _ := vaultwire.NewKey()
	f.ownerPrivate = owner.Bytes()
	ownerBox, _ := vaultwire.NewKey()
	for i := 0; i < 2; i++ {
		cfg, err := device.NewConfig(server.URL, "Fixture")
		if err != nil {
			t.Fatal(err)
		}
		cfg.OwnerID = f.user.key()
		cfg.OwnerPublic = owner.PublicKey().Bytes()
		cfg.OwnerBoxPublic = ownerBox.PublicKey().Bytes()
		cfg.Device.Role = "client"
		if i == 1 {
			cfg.Device.Role = "agent"
		}
		if err = store.Put(ctx, "devices", cfg.Device.ID, 0, deviceRecord{Device: cfg.Device, OwnerID: f.user.key(), CreatedAt: time.Now()}, nil); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			f.requester = device.New(cfg)
		} else {
			f.agent = device.New(cfg)
		}
	}
	return f
}

func (f *securityReviewFixture) browser(t *testing.T, path string, input any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://vault.example"+path, bytes.NewReader(raw))
	r.Header.Set("Origin", "https://vault.example")
	r.AddCookie(&http.Cookie{Name: f.s.cookie, Value: f.cookie})
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	return w
}
func (f *securityReviewFixture) verification(t *testing.T, purpose string) string {
	t.Helper()
	v := token()
	end := time.Now().Add(time.Minute)
	if err := f.store.Put(context.Background(), "verifications", hash(v), 0, verification{UserID: f.user.key(), Purpose: purpose}, &end); err != nil {
		t.Fatal(err)
	}
	return v
}
func (f *securityReviewFixture) pending(t *testing.T) device.Pending {
	t.Helper()
	p, err := f.requester.Submit(context.Background(), vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Fixture", Managed: true, AgentID: f.agent.Config.Device.ID, Reason: "Verify remote device revocation", Duration: 60})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := vaultwire.NewKey()
	receiver, err := vaultwire.Sign(f.agent.Config.PrivateKey, "receiver", vaultwire.Receiver{RequestID: p.Request.ID, RequestHash: vaultwire.Digest(p.Signed.Payload), PublicKey: key.PublicKey().Bytes(), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.agent.Call(context.Background(), "/api/v1/device/requests/"+p.Request.ID+"/receiver", map[string]any{"receiver": receiver}, nil); err != nil {
		t.Fatal(err)
	}
	p.Receiver = &receiver
	return p
}
func (f *securityReviewFixture) approve(t *testing.T, p device.Pending) *httptest.ResponseRecorder {
	t.Helper()
	key, _ := vaultwire.NewKey()
	box, err := vaultwire.Seal(key.PublicKey().Bytes(), "fixture", []byte("encrypted fixture grant"))
	if err != nil {
		t.Fatal(err)
	}
	return f.browser(t, "/api/v1/requests/"+p.Request.ID+"/approve", map[string]any{"box": box, "verification": f.verification(t, "approve:"+p.Request.ID)})
}

func TestSecurityReviewBrokerRejectsSecretClassConfusion(t *testing.T) {
	f := newSecurityReviewFixture(t)
	for _, q := range []vaultwire.Request{
		{Kind: "ethereum", IdentityType: "ssh", Managed: true},
		{Kind: "ethereum", IdentityType: "ethereum"},
		{Kind: "bitcoin", IdentityType: "bitcoin"},
		{Kind: "autofill", IdentityType: "payment-card", Payload: []byte(`{"provider":"login"}`)},
	} {
		q.ID = device.RandomID()
		q.DeviceID = f.requester.Config.Device.ID
		q.AgentID = f.agent.Config.Device.ID
		q.Session = "review-scope"
		q.Reason = "Reject a mismatched approval scope"
		q.Duration = 60
		q.CreatedAt = time.Now()
		q.ExpiresAt = q.CreatedAt.Add(time.Minute)
		signed, err := vaultwire.Sign(f.requester.Config.PrivateKey, "request", q)
		if err != nil {
			t.Fatal(err)
		}
		err = f.requester.Call(context.Background(), "/api/v1/device/requests", map[string]any{"signed": signed}, nil)
		var apiErr *device.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != 400 {
			t.Fatalf("%s/%s accepted or wrong error: %v", q.Kind, q.IdentityType, err)
		}
	}
}

func TestSecurityReviewManagedReceiverRequiresPairedSigningAgent(t *testing.T) {
	f := newSecurityReviewFixture(t)
	ctx := context.Background()
	_, err := f.requester.Submit(ctx, vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Fixture", Managed: true, AgentID: f.requester.Config.Device.ID, Reason: "Attempt to make a client its own signer", Duration: 60})
	var apiErr *device.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("client-only device accepted as signing agent: %v", err)
	}

	q := vaultwire.Request{ID: device.RandomID(), DeviceID: f.requester.Config.Device.ID, AgentID: f.agent.Config.Device.ID, Session: "receiver-substitution", Kind: "ssh", IdentityType: "ssh", Identity: "Fixture", Managed: true, Reason: "Attempt to supply a managed receiver", Duration: 60, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	signed, err := vaultwire.Sign(f.requester.Config.PrivateKey, "request", q)
	if err != nil {
		t.Fatal(err)
	}
	key, err := vaultwire.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	// Even an otherwise valid receiver must be registered through the signing
	// agent's own authenticated connection, not supplied by the requester.
	receiver, err := vaultwire.Sign(f.agent.Config.PrivateKey, "receiver", vaultwire.Receiver{RequestID: q.ID, RequestHash: vaultwire.Digest(signed.Payload), PublicKey: key.PublicKey().Bytes(), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	err = f.requester.Call(ctx, "/api/v1/device/requests", map[string]any{"signed": signed, "receiver": receiver}, nil)
	if !errors.As(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("requester-provided managed receiver accepted: %v", err)
	}
	p, err := f.requester.Submit(ctx, vaultwire.Request{Kind: "ssh", IdentityType: "ssh", Identity: "Fixture", Managed: true, AgentID: f.agent.Config.Device.ID, Reason: "Attempt to register a receiver as requester", Duration: 60})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err = vaultwire.Sign(f.requester.Config.PrivateKey, "receiver", vaultwire.Receiver{RequestID: p.Request.ID, RequestHash: vaultwire.Digest(p.Signed.Payload), PublicKey: key.PublicKey().Bytes(), ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.requester.Call(ctx, "/api/v1/device/requests/"+p.Request.ID+"/receiver", map[string]any{"receiver": receiver}, nil); err == nil {
		t.Fatal("requester registered the managed receiver")
	}
}

func TestSecurityReviewRevokingEitherParticipantStopsRemoteAccess(t *testing.T) {
	for _, revokeAgent := range []bool{false, true} {
		t.Run(map[bool]string{false: "requester", true: "agent"}[revokeAgent], func(t *testing.T) {
			f := newSecurityReviewFixture(t)
			p := f.pending(t)
			waiting := f.pending(t)
			if w := f.approve(t, p); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if state, err := f.agent.Status(context.Background(), p.Request.ID); err != nil || state.Status != "approved" {
				t.Fatal("fixture not active", err)
			}
			listRequests := func() []vaultwire.RequestState {
				t.Helper()
				r := httptest.NewRequest(http.MethodGet, "https://vault.example/api/v1/requests", nil)
				r.AddCookie(&http.Cookie{Name: f.s.cookie, Value: f.cookie})
				w := httptest.NewRecorder()
				f.s.Handler().ServeHTTP(w, r)
				var out struct {
					Requests []vaultwire.RequestState `json:"requests"`
				}
				if w.Code != http.StatusOK {
					t.Fatal(w.Code, w.Body.String())
				}
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				return out.Requests
			}
			if got := listRequests(); len(got) != 2 {
				t.Fatalf("request list omitted pending or active fixture: %d", len(got))
			}
			revoked, survivor := f.requester, f.agent
			if revokeAgent {
				revoked, survivor = f.agent, f.requester
			}
			if w := f.browser(t, "/api/v1/devices/"+revoked.Config.Device.ID+"/revoke", map[string]any{}); w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			if state, err := survivor.Status(context.Background(), p.Request.ID); err == nil && state.Status == "approved" {
				t.Fatal("other participant still sees active grant after device revocation")
			}
			if w := f.approve(t, waiting); w.Code == 200 {
				t.Fatal("request could be approved after participant revocation")
			}
			if got := listRequests(); len(got) != 0 {
				t.Fatalf("request list advertised revoked participant's access: %d", len(got))
			}
			if !revokeAgent {
				var inbox struct {
					Requests []vaultwire.RequestState `json:"requests"`
				}
				if err := f.agent.Call(context.Background(), "/api/v1/device/inbox", map[string]any{}, &inbox); err != nil {
					t.Fatal(err)
				}
				if len(inbox.Requests) != 0 {
					t.Fatal("agent inbox retained revoked requester's approvals")
				}
			}
		})
	}
}

func TestSecurityReviewRateLimitDoesNotBlockOtherAccounts(t *testing.T) {
	f := newSecurityReviewFixture(t)
	ctx := context.Background()
	spec := vaultwire.Request{Kind: "credentials", IdentityType: "github", Payload: []byte(`{"provider":"github","mode":"command"}`), Reason: "Exercise isolated request admission", Duration: 60}
	for i := 0; i < 30; i++ {
		if _, err := f.requester.Submit(ctx, spec); err != nil {
			t.Fatalf("fixture request %d rejected early: %v", i, err)
		}
	}
	if _, err := f.requester.Submit(ctx, spec); err == nil {
		t.Fatal("request burst was not limited")
	}
	other, err := device.NewConfig(f.requester.Config.Server, "Other account")
	if err != nil {
		t.Fatal(err)
	}
	other.OwnerID = "separate-owner"
	if err = f.store.Put(ctx, "devices", other.Device.ID, 0, deviceRecord{Device: other.Device, OwnerID: other.OwnerID, CreatedAt: time.Now()}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = device.New(other).Submit(ctx, spec); err != nil {
		t.Fatal("one account exhausted another account's request allowance:", err)
	}
}
