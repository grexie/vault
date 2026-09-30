package cloudstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestEncryptedRecords(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	mem := NewMemory()
	s, e := New(mem, key)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	sensitive := map[string]string{"name": "personal bitcoin", "private": "never-visible-to-mongodb"}
	if e = s.Put(ctx, "alice-identities", "id1", 0, sensitive, nil); e != nil {
		t.Fatal(e)
	}
	for _, d := range mem.Docs {
		if bytes.Contains(d.Payload, []byte(sensitive["private"])) || d.Scope == "alice-identities" || d.ID == "id1" {
			t.Fatal("plaintext leaked")
		}
	}
	var got map[string]string
	v, e := s.Get(ctx, "alice-identities", "id1", &got)
	if e != nil || v != 1 || got["private"] != sensitive["private"] {
		t.Fatal("decrypt failed", e)
	}
	if _, e = s.Get(ctx, "bob-identities", "id1", &got); !errors.Is(e, ErrNotFound) {
		t.Fatal("cross-account read", e)
	}
	if e = s.Put(ctx, "alice-identities", "id1", 0, sensitive, nil); !errors.Is(e, ErrConflict) {
		t.Fatal("overwrite allowed")
	}
	restarted, _ := New(mem, key)
	if _, e = restarted.Get(ctx, "alice-identities", "id1", &got); e != nil {
		t.Fatal("restart lost access", e)
	}
	for id, d := range mem.Docs {
		d.Version++
		mem.Docs[id] = d
	}
	if _, e = s.Get(ctx, "alice-identities", "id1", &got); e == nil {
		t.Fatal("version tampering accepted")
	}
	past := time.Now().Add(-time.Second)
	s.Put(ctx, "sessions", "expired", 0, sensitive, &past)
	if _, e = s.Get(ctx, "sessions", "expired", &got); !errors.Is(e, ErrNotFound) {
		t.Fatal("expired session accepted")
	}
}
