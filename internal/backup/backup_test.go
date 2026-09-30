package backup

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestBackupAuthentication(t *testing.T) {
	password := []byte("a long temporary test password")
	plain := []byte(`{"identities":[{"name":"fixture","secret":"never-in-the-file"}]}`)
	encrypted, e := Encrypt(password, plain)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(encrypted, []byte("never-in-the-file")) || bytes.Contains(encrypted, password) {
		t.Fatal("plaintext leaked")
	}
	got, e := Decrypt(password, encrypted)
	if e != nil || !bytes.Equal(got, plain) {
		t.Fatal("roundtrip", e)
	}
	if _, e = Decrypt([]byte("a different temporary password"), encrypted); e == nil {
		t.Fatal("wrong password accepted")
	}
	var f File
	json.Unmarshal(encrypted, &f)
	f.Ciphertext[len(f.Ciphertext)-1] ^= 1
	b, _ := json.Marshal(f)
	if _, e = Decrypt(password, b); e == nil {
		t.Fatal("tampered backup accepted")
	}
	f.KDF.Memory = 4 * 1024 * 1024
	b, _ = json.Marshal(f)
	if _, e = Decrypt(password, b); e == nil {
		t.Fatal("attacker-controlled KDF accepted")
	}
	if _, e = Encrypt([]byte("short"), plain); e == nil {
		t.Fatal("weak password accepted")
	}
}
