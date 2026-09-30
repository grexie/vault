// Package cloudstore encrypts application records before they reach MongoDB.
// Key-bearing identity payloads must additionally be encrypted by their owner.
package cloudstore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var ErrNotFound = errors.New("record not found")
var ErrConflict = errors.New("record changed; try again")

type Document struct {
	ID        string     `bson:"_id"`
	Scope     string     `bson:"scope"`
	Version   int64      `bson:"version"`
	Payload   []byte     `bson:"payload"`
	ExpiresAt *time.Time `bson:"expiresAt,omitempty"`
}

type Backend interface {
	Get(context.Context, string) (Document, error)
	List(context.Context, string) ([]Document, error)
	Put(context.Context, Document, int64) error
	Delete(context.Context, string) error
	Close(context.Context) error
}

type Store struct {
	backend  Backend
	aead     cipher.AEAD
	indexKey []byte
}

func New(backend Backend, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("storage encryption key must be 32 bytes")
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return nil, e
	}
	h := hmac.New(sha256.New, key)
	h.Write([]byte("grexie-vault/index/v1"))
	return &Store{backend: backend, aead: aead, indexKey: h.Sum(nil)}, nil
}
func (s *Store) token(domain, value string) string {
	h := hmac.New(sha256.New, s.indexKey)
	h.Write([]byte(domain + "\x00" + value))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Store) docID(scope, id string) string { return s.token("record", scope+"\x00"+id) }
func (s *Store) Open(d Document, out any) error {
	if d.ExpiresAt != nil && !time.Now().Before(*d.ExpiresAt) {
		return ErrNotFound
	}
	if len(d.Payload) < s.aead.NonceSize()+s.aead.Overhead() {
		return errors.New("invalid encrypted record")
	}
	aad := documentAAD(d)
	plain, e := s.aead.Open(nil, d.Payload[:s.aead.NonceSize()], d.Payload[s.aead.NonceSize():], aad)
	if e != nil {
		return errors.New("encrypted record authentication failed")
	}
	defer clear(plain)
	return json.Unmarshal(plain, out)
}
func (s *Store) Get(ctx context.Context, scope, id string, out any) (int64, error) {
	d, e := s.backend.Get(ctx, s.docID(scope, id))
	if e != nil {
		return 0, e
	}
	if d.ID != s.docID(scope, id) || d.Scope != s.token("scope", scope) {
		return 0, errors.New("encrypted record binding mismatch")
	}
	return d.Version, s.Open(d, out)
}
func (s *Store) List(ctx context.Context, scope string) ([]Document, error) {
	docs, err := s.backend.List(ctx, s.token("scope", scope))
	if err != nil {
		return nil, err
	}
	for _, d := range docs {
		if d.Scope != s.token("scope", scope) {
			return nil, errors.New("encrypted record scope mismatch")
		}
	}
	return docs, nil
}

// expected=0 creates, otherwise it is an optimistic compare-and-swap version.
func (s *Store) Put(ctx context.Context, scope, id string, expected int64, value any, expires *time.Time) error {
	b, e := json.Marshal(value)
	if e != nil {
		return e
	}
	defer clear(b)
	d := Document{ID: s.docID(scope, id), Scope: s.token("scope", scope), Version: expected + 1, ExpiresAt: expires}
	nonce := make([]byte, s.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	aad := documentAAD(d)
	d.Payload = s.aead.Seal(nonce, nonce, b, aad)
	return s.backend.Put(ctx, d, expected)
}
func (s *Store) Delete(ctx context.Context, scope, id string) error {
	return s.backend.Delete(ctx, s.docID(scope, id))
}
func (s *Store) Close(ctx context.Context) error { return s.backend.Close(ctx) }

// Memory is an encrypted-record backend for isolated tests, never a production fallback.
type Memory struct {
	mu   sync.Mutex
	Docs map[string]Document
}

func NewMemory() *Memory { return &Memory{Docs: map[string]Document{}} }
func (m *Memory) Get(_ context.Context, id string) (Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.Docs[id]
	if !ok {
		return d, ErrNotFound
	}
	d.Payload = append([]byte(nil), d.Payload...)
	return d, nil
}
func (m *Memory) List(_ context.Context, scope string) ([]Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []Document{}
	for _, d := range m.Docs {
		if d.Scope == scope {
			d.Payload = append([]byte(nil), d.Payload...)
			out = append(out, d)
		}
	}
	return out, nil
}
func (m *Memory) Put(_ context.Context, d Document, expected int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.Docs[d.ID]
	if ok && old.Version != expected || !ok && expected != 0 || ok && expected == 0 {
		return ErrConflict
	}
	d.Payload = append([]byte(nil), d.Payload...)
	m.Docs[d.ID] = d
	return nil
}
func (m *Memory) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Docs, id)
	return nil
}
func (m *Memory) Close(context.Context) error { return nil }

type Mongo struct {
	client  *mongo.Client
	records *mongo.Collection
}

func Connect(ctx context.Context, uri, database string, key []byte) (*Store, error) {
	if database == "" || uri == "" {
		return nil, errors.New("MongoDB URI and database are required")
	}
	client, e := mongo.Connect(options.Client().ApplyURI(uri))
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*Store, error) { client.Disconnect(context.Background()); return nil, err }
	if e = client.Ping(ctx, nil); e != nil {
		return fail(e)
	}
	b := &Mongo{client: client, records: client.Database(database).Collection("encrypted_records")}
	_, e = b.records.Indexes().CreateMany(ctx, []mongo.IndexModel{{Keys: bson.D{{Key: "scope", Value: 1}}}, {Keys: bson.D{{Key: "expiresAt", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)}})
	if e != nil {
		return fail(e)
	}
	s, e := New(b, key)
	if e != nil {
		return fail(e)
	}
	return s, nil
}
func (m *Mongo) Get(ctx context.Context, id string) (Document, error) {
	var d Document
	e := m.records.FindOne(ctx, bson.M{"_id": id}).Decode(&d)
	if errors.Is(e, mongo.ErrNoDocuments) {
		e = ErrNotFound
	}
	return d, e
}
func (m *Mongo) List(ctx context.Context, scope string) ([]Document, error) {
	cur, e := m.records.Find(ctx, bson.M{"scope": scope}, options.Find().SetLimit(2000))
	if e != nil {
		return nil, e
	}
	defer cur.Close(ctx)
	var out []Document
	e = cur.All(ctx, &out)
	return out, e
}
func (m *Mongo) Put(ctx context.Context, d Document, expected int64) error {
	if expected == 0 {
		_, e := m.records.InsertOne(ctx, d)
		if mongo.IsDuplicateKeyError(e) {
			return ErrConflict
		}
		return e
	}
	r, e := m.records.ReplaceOne(ctx, bson.M{"_id": d.ID, "version": expected}, d)
	if e != nil {
		return e
	}
	if r.MatchedCount != 1 {
		return ErrConflict
	}
	return nil
}
func (m *Mongo) Delete(ctx context.Context, id string) error {
	_, e := m.records.DeleteOne(ctx, bson.M{"_id": id})
	return e
}
func (m *Mongo) Close(ctx context.Context) error { return m.client.Disconnect(ctx) }

func documentAAD(d Document) []byte {
	expires := "none"
	if d.ExpiresAt != nil {
		expires = fmt.Sprint(d.ExpiresAt.UnixMilli())
	}
	return []byte(fmt.Sprintf("grexie-vault/mongo/v1:%s:%s:%d:%s", d.ID, d.Scope, d.Version, expires))
}
