package cloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/grexie/vault/internal/cloudstore"
)

func TestPersistentSessionAndOriginBoundary(t *testing.T) {
	ctx := context.Background()
	key := random(32)
	backend := cloudstore.NewMemory()
	store, _ := cloudstore.New(backend, key)
	cfg := Config{Origin: "https://vault.example", Version: "fixture"}
	s, e := New(ctx, cfg, store, nil)
	if e != nil {
		t.Fatal(e)
	}
	u := User{ID: random(32), Name: "Fixture"}
	store.Put(ctx, "users", u.key(), 0, u, nil)
	recorder := httptest.NewRecorder()
	r := httptest.NewRequest("POST", cfg.Origin+"/", nil)
	if e = s.establish(recorder, r, u); e != nil {
		t.Fatal(e)
	}
	cookie := recorder.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge < 86400 {
		t.Fatal("cookie is not securely persistent")
	}
	reopened, _ := cloudstore.New(backend, key)
	restarted, e := New(ctx, cfg, reopened, nil)
	if e != nil {
		t.Fatal(e)
	}
	call := func(path, origin string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", cfg.Origin+path, strings.NewReader(`{}`))
		r.AddCookie(cookie)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		restarted.Handler().ServeHTTP(w, r)
		return w
	}
	good := call("/api/v1/session/wrapping-key", cfg.Origin)
	if good.Code != 200 {
		t.Fatal("restart lost session", good.Body.String())
	}
	if call("/api/v1/session/wrapping-key", "").Code != 403 || call("/api/v1/session/wrapping-key", "https://attacker.example").Code != 403 {
		t.Fatal("CSRF accepted")
	}
	if call("/api/v1/logout", cfg.Origin).Code != 200 {
		t.Fatal("logout failed")
	}
	if call("/api/v1/session/wrapping-key", cfg.Origin).Code != 401 {
		t.Fatal("revoked cookie reused")
	}
	expiry := time.Now().Add(-time.Second)
	session := Session{UserID: u.key(), Wrap: random(32), ExpiresAt: expiry}
	store.Put(ctx, "sessions", hash(cookie.Value), 0, session, nil)
	if call("/api/v1/session/wrapping-key", cfg.Origin).Code != 401 {
		t.Fatal("expired session accepted")
	}
}
