//go:build unix

package bridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grexie/vault/internal/app"
)

func TestRevokeAfterRestartAndJobIsolation(t *testing.T) {
	for _, mode := range []string{"lease", "connection"} {
		t.Run(mode, func(t *testing.T) {
			fallback := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/revoke" {
					fallback = true
					if r.Header.Get("Authorization") != "Bearer paired-fixture" {
						t.Error("incorrect pairing credential")
					}
					w.Write([]byte(`{"ok":true}`))
					return
				}
				w.WriteHeader(401)
				w.Write([]byte(`{"error":"Unknown request capability"}`))
			}))
			defer server.Close()
			c := Config{Server: server.URL, Token: "paired-fixture"}
			state, alias, lock, e := paths(c, "restart-cleanup")
			if e != nil {
				t.Fatal(e)
			}
			defer os.Remove(state)
			defer os.Remove(alias)
			defer os.Remove(lock)
			l := Lease{Config: c, Capability: "old-capability", Request: app.Request{ID: "old-request", Mode: mode, Session: "restart-cleanup", Socket: filepath.Join(t.TempDir(), "agent.sock")}}
			b, _ := json.Marshal(l)
			os.WriteFile(state, b, 0600)
			err := Revoke(context.Background(), c, "restart-cleanup")
			if mode == "lease" {
				if err != nil || !fallback {
					t.Fatalf("paired cleanup failed: %v", err)
				}
				if _, e = os.Stat(state); !os.IsNotExist(e) {
					t.Fatal("stale state retained")
				}
			} else {
				if err == nil || fallback {
					t.Fatal("job used pairing fallback")
				}
			}
		})
	}
}

func TestEnsureCannotReplaceLockedPersistentGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(app.Request{ID: "grant", Mode: "persistent", Status: "locked"})
	}))
	defer server.Close()
	c := Config{Server: server.URL, Token: "paired-fixture"}
	state, alias, lock, e := paths(c, "persistent")
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(state)
	defer os.Remove(alias)
	defer os.Remove(lock)
	l := Lease{Config: c, ConnectionToken: "keep-this-token", Request: app.Request{ID: "grant", Mode: "persistent", Session: "persistent"}}
	b, _ := json.Marshal(l)
	os.WriteFile(state, b, 0600)
	if _, e = Request(context.Background(), c, "persistent", "A different operation", time.Minute, "ssh", true, false, nil); e == nil {
		t.Fatal("replaced a persistent grant")
	}
	got, e := os.ReadFile(state)
	if e != nil || string(got) != string(b) {
		t.Fatal("lost the persistent token")
	}
}
