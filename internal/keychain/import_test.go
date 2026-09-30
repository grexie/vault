package keychain

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"strings"
	"testing"
)

func TestScopedCSV(t *testing.T) {
	csv := "Title,URL,Username,Password,Notes\nUnrelated,https://elsewhere.example/a,other,do-not-import,\nRequested,https://example.com/login,fixture,fixture-password,\n"
	in := Intent{Source: "safari", Origin: "https://example.com", Username: "fixture"}
	c, e := FromCSV(strings.NewReader(csv), in)
	if e != nil || c.Fields["password"] != "fixture-password" {
		t.Fatal("scoped import failed", e)
	}
	in.Origin = "https://example.com.evil.test"
	if _, e = FromCSV(strings.NewReader(csv), in); e == nil {
		t.Fatal("origin mismatch accepted")
	}
	in.Origin = "https://example.com"
	in.Username = ""
	if _, e = FromCSV(strings.NewReader(csv+"Requested2,https://example.com/another,another,another-password,\n"), in); e == nil {
		t.Fatal("ambiguous account accepted")
	}
}
func TestChromeCipherFixtures(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	plain := []byte("disposable-fixture-password")
	pad := 16 - len(plain)%16
	b := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(key)
	cipher.NewCBCEncrypter(block, bytes.Repeat([]byte{' '}, 16)).CryptBlocks(b, b)
	raw := append([]byte("v10"), b...)
	out, e := decryptChrome(key, raw)
	if e != nil || !bytes.Equal(out, plain) {
		t.Fatal("Chrome compatibility round trip failed", e)
	}
	raw[1] = '2'
	if _, e = decryptChrome(key, raw); e == nil {
		t.Fatal("unknown Chrome format silently accepted")
	}
}
