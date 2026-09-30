package app

import (
	"github.com/grexie/vault/internal/proof"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type grantLease struct {
	lease
	ConnectionToken string `json:"connectionToken"`
}

func (h *harness) grant(session string, idle int) grantLease {
	var g grantLease
	h.call("POST", "/v1/requests", h.token, map[string]any{"session": session, "reason": "GitHub deployment integration test", "access": "ssh", "mode": "persistent", "idleSeconds": idle}, &g, 201)
	return g
}
func (h *harness) connectGrant(g grantLease, name string) lease {
	var l lease
	h.call("POST", "/v1/grants/"+g.Request.ID+"/connect", g.ConnectionToken, map[string]any{"session": name, "socket": "/tmp/" + name + ".sock", "durationSeconds": 60}, &l, 201)
	return l
}
func TestPersistentIdleReapprovalAndRevocation(t *testing.T) {
	h := newHarness(t)
	g := h.grant("github-ci", 30*86400)
	h.approve(g.lease)
	a := h.connectGrant(g, "job-a")
	b := h.connectGrant(g, "job-b")
	h.sign(a, 200)
	h.sign(b, 200)
	if a.Request.Socket == b.Request.Socket || a.Capability == b.Capability {
		t.Fatal("jobs not isolated")
	}
	h.call("POST", "/v1/requests/"+a.Request.ID+"/revoke", a.Capability, map[string]any{}, nil, 200)
	h.sign(a, 403)
	h.sign(b, 200)
	h.call("POST", "/v1/grants/"+g.Request.ID+"/connect", a.Capability, map[string]any{"session": "unauthorized", "socket": "/tmp/bad.sock", "durationSeconds": 60}, nil, 401)
	h.s.mu.Lock()
	h.s.state.Requests[g.Request.ID].LastUsedAt = time.Now().Add(-31 * 24 * time.Hour)
	h.s.mu.Unlock()
	var q Request
	h.call("GET", "/v1/requests/"+g.Request.ID, g.Capability, nil, &q, 200)
	if q.Status != "locked" {
		t.Fatal("idle grant did not lock")
	}
	h.sign(b, 403)
	c := h.connectGrant(g, "job-c")
	d := h.connectGrant(g, "job-d")
	if c.Request.Status != "pending" || d.Request.Status != "pending" {
		t.Fatal("connect did not wait for approval")
	}
	h.sign(c, 403)
	h.approve(g.lease)
	h.sign(c, 200)
	h.sign(d, 200)
	h.call("POST", "/api/requests/"+g.Request.ID+"/revoke", "", map[string]any{}, nil, 200)
	h.sign(c, 403)
	h.sign(d, 403)
	h.call("POST", "/v1/grants/"+g.Request.ID+"/connect", g.ConnectionToken, map[string]any{"session": "revoked", "socket": "/tmp/revoked.sock", "durationSeconds": 60}, nil, 401)
}

func TestPersistentDenialRetainsTokenAndRestartLocks(t *testing.T) {
	h := newHarness(t)
	g := h.grant("restart-ci", 30*86400)
	h.approve(g.lease)
	h.s.mu.Lock()
	h.s.endLocked(h.s.state.Requests[g.Request.ID], "locked", "inactivity")
	h.s.persistLocked()
	h.s.mu.Unlock()
	a := h.connectGrant(g, "denied-job")
	h.call("POST", "/api/requests/"+g.Request.ID+"/revoke", "", map[string]any{}, nil, 200)
	h.sign(a, 403)
	b := h.connectGrant(g, "retry-job")
	h.approve(g.lease)
	h.sign(b, 200)
	if err := h.s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(h.s.config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.state.Requests[g.Request.ID].Status != "locked" || s.state.Grants[g.Request.ID].ConnectionHash != tokenHash(g.ConnectionToken) {
		t.Fatal("restart lost grant or left it unlocked")
	}
	r := httptest.NewRequest(http.MethodGet, h.origin+"/v1/requests/"+g.Request.ID, nil)
	r.Header.Set("Authorization", "Bearer "+g.Capability)
	proof.Sign(r, nil, h.requestKeys[g.Request.ID])
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("management capability not persistent")
	}
	if s.state.Requests[b.Request.ID].Status != "revoked" {
		t.Fatal("restart left child connection active")
	}
}

func TestPersistentStatusPollingDoesNotRenewIdle(t *testing.T) {
	h := newHarness(t)
	g := h.grant("short-idle", 1)
	h.approve(g.lease)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		var q Request
		h.call("GET", "/v1/requests/"+g.Request.ID, g.Capability, nil, &q, 200)
		if q.Status == "locked" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("polling kept grant unlocked")
}
