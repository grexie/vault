package cloudstore

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"
)

// Authorization and revocation callers must never mistake a truncated list
// for the complete set of grants. Exercise the actual Mongo query boundary.
func TestSecurityReviewMongoListOverflowFailsClosed(t *testing.T) {
	uri := os.Getenv("VAULT_TEST_MONGODB")
	if uri == "" {
		t.Skip("set VAULT_TEST_MONGODB for isolated MongoDB integration")
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "mongodb" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil {
		t.Fatal("integration database must be loopback-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("vault_security_review_%d", time.Now().UnixNano())
	s, err := Connect(ctx, uri, name, key)
	if err != nil {
		t.Fatal(err)
	}
	m := s.backend.(*Mongo)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := m.client.Database(name).Drop(cleanup); err != nil {
			t.Errorf("remove isolated test database: %v", err)
		}
		if err := s.Close(cleanup); err != nil {
			t.Errorf("close isolated test database: %v", err)
		}
	})
	const scope = "requests:generated-owner-fixture"
	for i := 0; i < 2000; i++ {
		if err := s.Put(ctx, scope, fmt.Sprint(i), 0, i, nil); err != nil {
			t.Fatal(err)
		}
	}
	checkComplete := func() {
		t.Helper()
		docs, err := s.List(ctx, scope)
		if err != nil || len(docs) != 2000 {
			t.Fatalf("boundary list = %d records, error %v; want all 2000", len(docs), err)
		}
		seen := make(map[int]bool)
		for _, doc := range docs {
			var value int
			if err := s.Open(doc, &value); err != nil || value < 0 || value >= 2000 || seen[value] {
				t.Fatalf("invalid or repeated encrypted fixture record: %d, %v", value, err)
			}
			seen[value] = true
		}
	}
	checkComplete()
	if err := s.Put(ctx, scope, "overflow", 0, "overflow fixture", nil); err != nil {
		t.Fatal(err)
	}
	if docs, err := m.List(ctx, s.token("scope", scope)); err == nil || docs != nil {
		t.Fatalf("overflow exposed a partial authorization view: %d records, error %v", len(docs), err)
	}
	if docs, err := s.List(ctx, scope); err == nil || docs != nil {
		t.Fatalf("store accepted overflow: %d records, error %v", len(docs), err)
	}
	if err := s.Put(ctx, "requests:unrelated-owner", "one", 0, "unrelated fixture", nil); err != nil {
		t.Fatal(err)
	}
	if docs, err := s.List(ctx, "requests:unrelated-owner"); err != nil || len(docs) != 1 {
		t.Fatalf("overflow affected an unrelated owner: %d records, error %v", len(docs), err)
	}
	if err := s.Delete(ctx, scope, "overflow"); err != nil {
		t.Fatal(err)
	}
	checkComplete()
}
