// Package backup implements the portable browser-only identity backup format.
// The hosted service does not expose a password or plaintext backup endpoint.
package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const MaxPlaintext = 8 * 1024 * 1024
const format = "grexie-vault-identities"

var aad = []byte("grexie-vault/backup/v1\x00argon2id\x00memory=65536,time=3,parallelism=1\x00aes-256-gcm")

type KDF struct {
	Name        string `json:"name"`
	Memory      uint32 `json:"memoryKiB"`
	Time        uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}
type File struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KDF        KDF    `json:"kdf"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func key(password, salt []byte) (cipher.AEAD, error) {
	k := argon2.IDKey(password, salt, 3, 64*1024, 1, 32)
	defer clear(k)
	block, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func Encrypt(password, plaintext []byte) ([]byte, error) {
	if !utf8.Valid(password) || utf8.RuneCount(password) < 12 || len(password) > 1024 {
		return nil, errors.New("choose a backup password of at least 12 characters (maximum 1024 bytes)")
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext || !json.Valid(plaintext) {
		return nil, errors.New("backup must be a JSON identity document under 8 MiB")
	}
	f := File{Format: format, Version: 1, KDF: KDF{"argon2id", 65536, 3, 1}, Salt: make([]byte, 16), Nonce: make([]byte, 12)}
	if _, e := rand.Read(f.Salt); e != nil {
		return nil, e
	}
	if _, e := rand.Read(f.Nonce); e != nil {
		return nil, e
	}
	aead, e := key(password, f.Salt)
	if e != nil {
		return nil, e
	}
	f.Ciphertext = aead.Seal(nil, f.Nonce, plaintext, aad)
	return json.MarshalIndent(f, "", "  ")
}
func Decrypt(password, encrypted []byte) ([]byte, error) {
	if len(encrypted) > 12*1024*1024 || len(password) > 1024 {
		return nil, errors.New("backup exceeds size limit")
	}
	var f File
	d := json.NewDecoder(bytes.NewReader(encrypted))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || d.Decode(new(any)) != io.EOF || f.Format != format || f.Version != 1 || f.KDF != (KDF{"argon2id", 65536, 3, 1}) || len(f.Salt) != 16 || len(f.Nonce) != 12 || len(f.Ciphertext) < 16 || len(f.Ciphertext) > MaxPlaintext+16 {
		return nil, errors.New("unsupported or malformed encrypted backup")
	}
	aead, e := key(password, f.Salt)
	if e != nil {
		return nil, e
	}
	plain, e := aead.Open(nil, f.Nonce, f.Ciphertext, aad)
	if e != nil {
		return nil, errors.New("incorrect password or damaged backup")
	}
	if !json.Valid(plain) {
		clear(plain)
		return nil, errors.New("invalid backup contents")
	}
	return plain, nil
}
