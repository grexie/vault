// Package proof binds a request capability to a client-generated key. This is
// proof of possession, not hardware attestation or an OS-user isolation boundary.
package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const Window = time.Minute

func payload(r *http.Request, digest [32]byte) []byte {
	token := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	return []byte(strings.Join([]string{"remote-ssh-agent/client-proof/v1", r.Method, r.Host, r.URL.EscapedPath(), r.URL.RawQuery, base64.RawURLEncoding.EncodeToString(digest[:]), base64.RawURLEncoding.EncodeToString(token[:]), r.Header.Get("X-SSH-Time"), r.Header.Get("X-SSH-Nonce")}, "\n"))
}

func Sign(r *http.Request, body []byte, key ed25519.PrivateKey) error {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	r.Header.Set("X-SSH-Time", strconv.FormatInt(time.Now().Unix(), 10))
	r.Header.Set("X-SSH-Nonce", base64.RawURLEncoding.EncodeToString(nonce))
	r.Header.Set("X-SSH-Proof", base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, payload(r, sha256.Sum256(body)))))
	return nil
}

func Verify(r *http.Request, digest [32]byte, key []byte) (string, bool) {
	if len(key) != ed25519.PublicKeySize {
		return "", false
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-SSH-Time"), 10, 64)
	if err != nil {
		return "", false
	}
	when := time.Unix(ts, 0)
	now := time.Now()
	if when.Before(now.Add(-Window)) || when.After(now.Add(Window)) {
		return "", false
	}
	nonce := r.Header.Get("X-SSH-Nonce")
	n, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(n) != 24 {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SSH-Proof"))
	if err != nil {
		return "", false
	}
	return nonce, ed25519.Verify(ed25519.PublicKey(key), payload(r, digest), sig)
}
