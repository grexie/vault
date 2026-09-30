// Package vaultwire is the public, versioned browser/device envelope protocol.
package vaultwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

type Signed struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}
type Envelope struct {
	PublicKey  []byte `json:"publicKey"`
	Salt       []byte `json:"salt"`
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}

func NewKey() (*ecdh.PrivateKey, error) { return ecdh.P256().GenerateKey(rand.Reader) }
func Public(private []byte) ([]byte, error) {
	k, e := ecdh.P256().NewPrivateKey(private)
	if e != nil {
		return nil, e
	}
	return k.PublicKey().Bytes(), nil
}
func ID(public []byte) string {
	h := sha256.Sum256(public)
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func Digest(b []byte) string         { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func ValidPublic(public []byte) bool { _, e := ecdh.P256().NewPublicKey(public); return e == nil }
func domainMessage(domain string, payload []byte) []byte {
	return append([]byte("grexie-vault/"+domain+"/v1\x00"), payload...)
}
func Sign(private []byte, domain string, value any) (Signed, error) {
	b, e := json.Marshal(value)
	if e != nil {
		return Signed{}, e
	}
	return SignBytes(private, domain, b)
}
func SignBytes(private []byte, domain string, b []byte) (Signed, error) {
	p, e := ecdh.P256().NewPrivateKey(private)
	if e != nil {
		return Signed{}, e
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), p.PublicKey().Bytes())
	k := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: new(big.Int).SetBytes(private)}
	digest := sha256.Sum256(domainMessage(domain, b))
	r, s, e := ecdsa.Sign(rand.Reader, k, digest[:])
	k.D.SetInt64(0)
	if e != nil {
		return Signed{}, e
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return Signed{Payload: b, Signature: sig}, nil
}
func Verify(public []byte, domain string, s Signed, out any) error {
	if len(s.Payload) > 8*1024*1024 || len(s.Signature) != 64 {
		return errors.New("invalid signed message")
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), public)
	if x == nil {
		return errors.New("invalid signing key")
	}
	digest := sha256.Sum256(domainMessage(domain, s.Payload))
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], new(big.Int).SetBytes(s.Signature[:32]), new(big.Int).SetBytes(s.Signature[32:])) {
		return errors.New("message signature rejected")
	}
	if domain == "request" {
		if _, e := DecodeRequest(s.Payload); e != nil {
			return e
		}
	}
	return json.Unmarshal(s.Payload, out)
}
func boxKey(secret, salt []byte, context string) (cipher.AEAD, error) {
	key := make([]byte, 32)
	defer clear(key)
	if _, e := io.ReadFull(hkdf.New(sha256.New, secret, salt, []byte("grexie-vault/box/v1\x00"+context)), key); e != nil {
		return nil, e
	}
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func Seal(public []byte, context string, plain []byte) (Envelope, error) {
	var out Envelope
	peer, e := ecdh.P256().NewPublicKey(public)
	if e != nil {
		return out, e
	}
	priv, e := NewKey()
	if e != nil {
		return out, e
	}
	secret, e := priv.ECDH(peer)
	if e != nil {
		return out, e
	}
	defer clear(secret)
	out.PublicKey = priv.PublicKey().Bytes()
	out.Salt = make([]byte, 32)
	out.IV = make([]byte, 12)
	if _, e = rand.Read(out.Salt); e != nil {
		return out, e
	}
	if _, e = rand.Read(out.IV); e != nil {
		return out, e
	}
	aead, e := boxKey(secret, out.Salt, context)
	if e != nil {
		return out, e
	}
	out.Ciphertext = aead.Seal(nil, out.IV, plain, []byte(context))
	return out, nil
}
func Open(private []byte, context string, in Envelope) ([]byte, error) {
	if len(in.Salt) != 32 || len(in.IV) != 12 || len(in.Ciphertext) < 16 || len(in.Ciphertext) > 8*1024*1024 {
		return nil, errors.New("invalid encrypted envelope")
	}
	priv, e := ecdh.P256().NewPrivateKey(private)
	if e != nil {
		return nil, e
	}
	pub, e := ecdh.P256().NewPublicKey(in.PublicKey)
	if e != nil {
		return nil, e
	}
	secret, e := priv.ECDH(pub)
	if e != nil {
		return nil, e
	}
	defer clear(secret)
	aead, e := boxKey(secret, in.Salt, context)
	if e != nil {
		return nil, e
	}
	return aead.Open(nil, in.IV, in.Ciphertext, []byte(context))
}
func PairMAC(secret, payload []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(domainMessage("pair", payload))
	return h.Sum(nil)
}
