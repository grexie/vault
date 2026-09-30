package cloudstore

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func TestMongoEncryptionAndRestart(t *testing.T) {
	uri := os.Getenv("VAULT_TEST_MONGODB")
	if uri == "" {
		t.Skip("set VAULT_TEST_MONGODB for isolated MongoDB integration")
	}
	if !strings.HasPrefix(uri, "mongodb://127.0.0.1:") {
		t.Fatal("integration database must be loopback-only")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	key := make([]byte, 32)
	rand.Read(key)
	name := fmt.Sprintf("vault_test_%d", time.Now().UnixNano())
	client, e := mongo.Connect(options.Client().ApplyURI(uri))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Disconnect(ctx)
	defer client.Database(name).Drop(ctx)
	s, e := Connect(ctx, uri, name, key)
	if e != nil {
		t.Fatal(e)
	}
	value := map[string]string{"cookie": "sensitive fixture cookie", "name": "private identity label"}
	expires := time.Now().Add(time.Hour)
	if e = s.Put(ctx, "alice", "session", 0, value, &expires); e != nil {
		t.Fatal(e)
	}
	var raw bson.M
	if e = client.Database(name).Collection("encrypted_records").FindOne(ctx, bson.M{}).Decode(&raw); e != nil {
		t.Fatal(e)
	}
	document, _ := bson.MarshalExtJSON(raw, false, false)
	if strings.Contains(string(document), "sensitive") || strings.Contains(string(document), "private identity") || strings.Contains(string(document), "alice") {
		t.Fatal("plaintext leaked into MongoDB")
	}
	s.Close(ctx)
	s, e = Connect(ctx, uri, name, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(ctx)
	var got map[string]string
	if _, e = s.Get(ctx, "alice", "session", &got); e != nil || got["cookie"] != value["cookie"] {
		t.Fatal("restart lost encrypted record", e)
	}
	if _, e = s.Get(ctx, "bob", "session", &got); e != ErrNotFound {
		t.Fatal("cross-account read", e)
	}
	var wg sync.WaitGroup
	var wins atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			if s.Put(ctx, "alice", "session", 1, value, &expires) == nil {
				wins.Add(1)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("CAS allowed concurrent overwrite", wins.Load())
	}
	_, e = client.Database(name).Collection("encrypted_records").UpdateOne(ctx, bson.M{}, bson.M{"$set": bson.M{"expiresAt": time.Now().Add(2 * time.Hour)}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, "alice", "session", &got); e == nil {
		t.Fatal("expiry tampering accepted")
	}
}
