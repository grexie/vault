package ageio

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/ssh"
)

func TestStreamingInteroperability(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []any{ed, rsaKey} {
		signer, _ := ssh.NewSignerFromKey(raw)
		recipient, err := ParseRecipient(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
		if err != nil {
			t.Fatal(err)
		}
		var identity age.Identity
		switch k := raw.(type) {
		case ed25519.PrivateKey:
			identity, _ = agessh.NewEd25519Identity(k)
		case *rsa.PrivateKey:
			identity, _ = agessh.NewRSAIdentity(k)
		}
		for _, armored := range []bool{false, true} {
			for _, payload := range [][]byte{nil, bytes.Repeat([]byte("large streaming document\x00\xff"), 10000)} {
				var encrypted, plain bytes.Buffer
				if err = Encrypt(&encrypted, bytes.NewReader(payload), []age.Recipient{recipient}, armored); err != nil {
					t.Fatal(err)
				}
				calls := 0
				if err = Decrypt(&plain, bytes.NewReader(encrypted.Bytes()), func(header []byte) ([]byte, error) { calls++; return age.DecryptHeader(header, identity) }); err != nil {
					t.Fatal(err)
				}
				if calls != 1 || !bytes.Equal(payload, plain.Bytes()) {
					t.Fatal("stream round-trip failed")
				}
				if !armored {
					reader, e := age.Decrypt(bytes.NewReader(encrypted.Bytes()), identity)
					if e != nil {
						t.Fatal(e)
					}
					actual, e := io.ReadAll(reader)
					if e != nil || !bytes.Equal(payload, actual) {
						t.Fatal("upstream age interoperability failed")
					}
					b := bytes.Clone(encrypted.Bytes())
					b[len(b)-1] ^= 1
					if Decrypt(io.Discard, bytes.NewReader(b), func(h []byte) ([]byte, error) { return age.DecryptHeader(h, identity) }) == nil {
						t.Fatal("tampered document accepted")
					}
				}
			}
		}
	}
}

func TestInvalidHeaderNeverRequestsApproval(t *testing.T) {
	for _, input := range []string{"not age", "age-encryption.org/v1\n-> test\n" + strings.Repeat("a", 70*1024)} {
		called := false
		err := Decrypt(io.Discard, strings.NewReader(input), func([]byte) ([]byte, error) { called = true; return nil, nil })
		if err == nil || called {
			t.Fatal("invalid header reached approval")
		}
	}
}
