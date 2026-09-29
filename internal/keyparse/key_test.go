package keyparse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
)

func TestExistingEncryptedFormats(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	password := []byte("synthetic-test-key-only")
	for name, key := range map[string]any{"Ed25519": ed, "RSA": rsaKey, "ECDSA": ec} {
		t.Run("OpenSSH/"+name, func(t *testing.T) {
			block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "generated test key", password)
			if err != nil {
				t.Fatal(err)
			}
			encoded := pem.EncodeToMemory(block)
			checkKey(t, encoded, password, key)
		})
	}
	// Legacy PEM encryption remains common in existing ~/.ssh/id_rsa files.
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), password, x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("legacy RSA PEM", func(t *testing.T) { checkKey(t, pem.EncodeToMemory(block), password, rsaKey) })
	for name, key := range map[string]any{"RSA": rsaKey, "ECDSA": ec, "Ed25519": ed} {
		t.Run("PKCS8/"+name, func(t *testing.T) {
			der, err := pkcs8.MarshalPrivateKey(key, password, nil)
			if err != nil {
				t.Fatal(err)
			}
			checkKey(t, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), password, key)
		})
	}
}
func checkKey(t *testing.T, data, password []byte, want any) {
	t.Helper()
	key, err := Parse(data, password)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := ssh.NewSignerFromKey(want)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(key.PublicKey()) != ssh.FingerprintSHA256(expected.PublicKey()) {
		t.Fatal("fingerprint mismatch")
	}
	compact, err := Compact(data, password)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Parse([]byte(compact), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(restored.PublicKey()) != ssh.FingerprintSHA256(expected.PublicKey()) {
		t.Fatal("compact fingerprint mismatch")
	}
	sig, err := restored.Sign(rand.Reader, []byte("compact round trip"))
	if err != nil {
		t.Fatal(err)
	}
	if err = expected.PublicKey().Verify([]byte("compact round trip"), sig); err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(data, []byte("wrong password")); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err = Parse(data, nil); err == nil {
		t.Fatal("missing password accepted")
	}
}
