// Package vault persists public metadata only. SSH keys and their encrypted
// largeBlob never enter this database.
package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Store struct{ db *bolt.DB }

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, "metadata.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if err = db.Update(func(tx *bolt.Tx) error { _, e := tx.CreateBucketIfNotExists([]byte("state")); return e }); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Load(v any) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("state")).Get([]byte("owner"))
		if b == nil {
			return nil
		}
		return json.Unmarshal(b, v)
	})
}

func (s *Store) Save(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("state")).Put([]byte("owner"), b) })
}

func (s *Store) Close() error { return s.db.Close() }
