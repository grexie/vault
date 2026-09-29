package app

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"filippo.io/age/agessh"
	"github.com/grexie/remote-ssh-agent/internal/access"
	"github.com/grexie/remote-ssh-agent/internal/limits"
	"github.com/grexie/remote-ssh-agent/internal/signer"
	"golang.org/x/crypto/ssh"
)

func validPublicKey(value, fingerprint string) bool {
	if len(value) > 16384 {
		return false
	}
	k, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(value))
	return err == nil && len(strings.TrimSpace(string(rest))) == 0 && ssh.FingerprintSHA256(k) == fingerprint
}

// Encryption needs only this public metadata; it creates no lease or push.
func (s *Server) ageRecipient(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clientLocked(r); !ok {
		fail(w, 401, "Client authentication failed")
		return
	}
	o := s.state.Owner
	if o == nil || o.PublicKey == "" {
		fail(w, 409, "Public recipient is not available yet; re-save the key or complete one approval, or supply --recipient/--recipients-file")
		return
	}
	if !validPublicKey(o.PublicKey, o.Fingerprint) {
		fail(w, 409, "Saved public recipient is invalid")
		return
	}
	if _, err := agessh.ParseRecipient(o.PublicKey); err != nil {
		fail(w, 400, "Age requires an RSA or Ed25519 SSH key")
		return
	}
	jsonReply(w, 200, map[string]string{"recipient": strings.TrimSpace(o.PublicKey), "fingerprint": o.Fingerprint})
}

func (s *Server) ageDecrypt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Header []byte `json:"header"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Header) == 0 || len(in.Header) > limits.MaxAgeHeader {
		fail(w, 400, "Age header must be between 1 byte and 64 KiB")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q, l, ok := s.leaseLocked(r)
	if !ok {
		fail(w, 401, "Unknown request capability")
		return
	}
	s.checkExpiryLocked(q)
	if !access.AllowsAge(q.Access) {
		fail(w, 403, "This lease does not allow age decryption")
		return
	}
	if q.Status != "active" || l.Worker == nil {
		fail(w, 403, "Decryption grant is locked")
		return
	}
	if q.Mode == "age-once" {
		hash := sha256.Sum256(in.Header)
		if base64.RawURLEncoding.EncodeToString(hash[:]) != q.HeaderHash {
			fail(w, 403, "This approval belongs to a different document")
			return
		}
	}
	reply, err := l.Worker.Do(signer.Message{Action: "age-decrypt", Data: in.Header})
	defer clear(reply.FileKey)
	if q.Mode == "age-once" {
		s.endLocked(q, "completed", "One-shot document decryption consumed")
		if persistErr := s.persistLocked(); persistErr != nil {
			s.errorInternal(w, persistErr)
			return
		}
	}
	var rejected *signer.OperationError
	if errors.As(err, &rejected) {
		fail(w, 400, rejected.Error())
		return
	}
	if err != nil || len(reply.FileKey) != 16 {
		s.endLocked(q, "revoked", "Decryption worker stopped")
		_ = s.persistLocked()
		fail(w, 403, "Worker is unavailable; grant closed")
		return
	}
	// Serialize key release with revocation, just like SSH signing.
	jsonReply(w, 200, reply)
}
