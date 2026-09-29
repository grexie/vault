//go:build unix

package bridge

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/grexie/remote-ssh-agent/internal/app"
)

func TestInheritedSocketRequiresLiveSSHLease(t *testing.T) {
	d, err := RuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	scratch, err := os.MkdirTemp(d, "inherit-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(scratch)
	socket := filepath.Join(scratch, "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	q := app.Request{ID: "fixture", Session: "inherited-test", Socket: socket, Access: "ssh", Status: "active", ExpiresAt: time.Now().Add(time.Minute)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/requests/fixture" || r.Header.Get("Authorization") != "Bearer fixture-capability" {
			t.Error("inherited lease made an unexpected request")
		}
		json.NewEncoder(w).Encode(q)
	}))
	defer server.Close()
	c := Config{Server: server.URL, Token: "fixture-pairing"}
	state, alias, lock, err := paths(c, q.Session)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(state)
	defer os.Remove(alias)
	defer os.Remove(lock)
	b, _ := json.Marshal(Lease{Config: c, Request: q, Capability: "fixture-capability"})
	if err := os.WriteFile(state, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(socket, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{socket, alias} {
		if found, err := InheritedSocket(context.Background(), c, path); !found || err != nil {
			t.Fatalf("approved socket rejected: %v", err)
		}
	}
	for _, test := range []struct {
		name, status, access string
		expiry               time.Time
	}{
		{"revoked", "revoked", "ssh", time.Now().Add(time.Minute)},
		{"pending", "pending", "ssh", time.Now().Add(time.Minute)},
		{"expired", "active", "ssh", time.Now().Add(-time.Minute)},
		{"age-only", "active", "age", time.Now().Add(time.Minute)},
	} {
		t.Run(test.name, func(t *testing.T) {
			q.Status, q.Access, q.ExpiresAt = test.status, test.access, test.expiry
			if found, err := InheritedSocket(context.Background(), c, socket); !found || err == nil {
				t.Fatal("unapproved inherited socket accepted")
			}
		})
	}
	if found, err := InheritedSocket(context.Background(), Config{Server: "https://other.invalid"}, socket); !found || err == nil {
		t.Fatal("different server accepted")
	}
	if found, err := InheritedSocket(context.Background(), c, "/tmp/ordinary-agent.sock"); found || err != nil {
		t.Fatal("ordinary agent selected")
	}
	if found, err := InheritedSocket(context.Background(), c, filepath.Join(scratch, "missing.sock")); !found || err == nil {
		t.Fatal("missing managed socket allowed fallback")
	}
	server.Close()
	if found, err := IsManagedSocket(socket); !found || err != nil {
		t.Fatal("network failure changed which socket the config selects")
	}
	if found, err := InheritedSocket(context.Background(), c, socket); !found || err == nil {
		t.Fatal("unavailable server allowed fallback")
	}
}
