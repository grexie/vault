package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/grexie/vault/internal/access"
	"github.com/grexie/vault/internal/limits"
	"github.com/grexie/vault/internal/signer"
	"golang.org/x/crypto/ssh"
)

var SessionPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func validFingerprint(f string) bool {
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(f, "SHA256:"))
	return strings.HasPrefix(f, "SHA256:") && err == nil && len(b) == 32
}
func textValid(s string, min, max int) bool {
	if len(strings.TrimSpace(s)) < min || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

func (s *Server) addClient(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !textValid(in.Name, 1, 80) {
		fail(w, 400, "Enter a client name")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Clients) >= 20 {
		fail(w, 409, "Remove an old client first")
		return
	}
	token := randomToken()
	c := Client{ID: randomToken(), Name: strings.TrimSpace(in.Name), CreatedAt: time.Now()}
	s.state.Clients[c.ID] = storedClient{Client: c, Hash: tokenHash(token)}
	if err := s.persistLocked(); err != nil {
		delete(s.state.Clients, c.ID)
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 201, map[string]any{"client": c, "token": token})
}
func (s *Server) removeClient(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := r.PathValue("id")
	delete(s.state.Clients, id)
	for _, q := range s.state.Requests {
		if q.ClientID == id && active(q) {
			s.endLocked(q, "revoked", "Client removed")
		}
	}
	if err := s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}

func (s *Server) requestCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Session     string `json:"session"`
		Reason      string `json:"reason"`
		Access      string `json:"access"`
		Mode        string `json:"mode"`
		HeaderHash  string `json:"headerHash"`
		Socket      string `json:"socket"`
		Duration    int    `json:"durationSeconds"`
		IdleSeconds int    `json:"idleSeconds"`
		RequestKey  []byte `json:"requestKey"`
	}
	if !decode(w, r, &in) {
		return
	}
	allowed, err := access.Normalize(in.Access)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	if in.Mode == "" {
		in.Mode = "lease"
	}
	validLease := in.Mode == "lease" && in.IdleSeconds == 0 && in.HeaderHash == "" && filepath.IsAbs(in.Socket) && textValid(in.Socket, 1, 104) && in.Duration >= 1 && in.Duration <= int(limits.MaxLeaseDuration/time.Second)
	hash, hashErr := base64.RawURLEncoding.DecodeString(in.HeaderHash)
	validOnce := in.Mode == "age-once" && in.IdleSeconds == 0 && allowed == access.Age && in.Socket == "" && in.Duration == 0 && hashErr == nil && len(hash) == 32
	validPersistent := in.Mode == "persistent" && in.IdleSeconds >= 1 && in.IdleSeconds <= int(limits.MaxIdleDuration/time.Second) && allowed == access.SSH && in.Socket == "" && in.Duration == 0 && in.HeaderHash == ""
	if len(in.RequestKey) != 32 || !SessionPattern.MatchString(in.Session) || !textValid(in.Reason, 8, 1000) || (!validLease && !validOnce && !validPersistent) {
		fail(w, 400, "A session and justification are required; leases need a socket and duration of 1s–48h, one-shot decryption needs a document header hash")
		return
	}
	s.mu.Lock()
	client, ok := s.clientLocked(r)
	if !ok {
		s.mu.Unlock()
		fail(w, 401, "Client authentication failed")
		return
	}
	if s.state.Owner == nil || s.state.Owner.Fingerprint == "" {
		s.mu.Unlock()
		fail(w, 409, "Save an SSH key in the phone keychain first")
		return
	}
	n := 0
	for _, q := range s.state.Requests {
		if active(q) {
			n++
			if q.ClientID == client.ID && q.Session == in.Session {
				s.mu.Unlock()
				fail(w, 409, "This session already has an open request")
				return
			}
		}
	}
	if n >= 16 {
		s.mu.Unlock()
		fail(w, 429, "Too many open requests")
		return
	}
	q := &Request{ID: randomToken(), ClientID: client.ID, ClientName: client.Name, Session: in.Session, Reason: strings.TrimSpace(in.Reason), Access: allowed, Mode: in.Mode, RequestKey: in.RequestKey, IdleSeconds: in.IdleSeconds, HeaderHash: in.HeaderHash, Socket: in.Socket, KeyName: s.state.Owner.KeyName, Fingerprint: s.state.Owner.Fingerprint, DurationSeconds: in.Duration, Status: "pending", CreatedAt: time.Now(), PendingUntil: time.Now().Add(5 * time.Minute), Notification: "sending"}
	cap := randomToken()
	s.state.Requests[q.ID] = q
	s.live[q.ID] = &liveRequest{CapabilityHash: tokenHash(cap)}
	connectionToken := ""
	if validPersistent {
		connectionToken = randomToken()
		s.state.Grants[q.ID] = grantSecrets{CapabilityHash: tokenHash(cap), ConnectionHash: tokenHash(connectionToken)}
	}
	// Bound the audit history without removing live requests.
	if len(s.state.Requests) > 500 {
		old := []*Request{}
		for _, v := range s.state.Requests {
			if !active(v) {
				old = append(old, v)
			}
		}
		sort.Slice(old, func(i, j int) bool { return old[i].CreatedAt.Before(old[j].CreatedAt) })
		for len(s.state.Requests) > 500 && len(old) > 0 {
			delete(s.state.Requests, old[0].ID)
			delete(s.live, old[0].ID)
			delete(s.state.Grants, old[0].ID)
			old = old[1:]
		}
	}
	if err := s.persistLocked(); err != nil {
		s.mu.Unlock()
		s.errorInternal(w, err)
		return
	}
	copy := *q
	s.mu.Unlock()
	go s.notify(q.ID)
	jsonReply(w, 201, map[string]any{"request": copy, "capability": cap, "connectionToken": connectionToken})
}

func (s *Server) requestStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, _, ok := s.leaseLocked(r)
	if !ok {
		fail(w, 401, "Unknown request capability")
		return
	}
	s.checkExpiryLocked(q)
	jsonReply(w, 200, q)
}
func (s *Server) capabilityRevoke(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q, _, ok := s.leaseLocked(r)
	if !ok {
		fail(w, 401, "Unknown request capability")
		return
	}
	if active(q) {
		s.endLocked(q, "revoked", "CLI session ended")
	}
	if err := s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 200, q)
}
func (s *Server) clientRevoke(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Session string `json:"session"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clientLocked(r)
	if !ok {
		fail(w, 401, "Client authentication failed")
		return
	}
	for _, q := range s.state.Requests {
		if q.ClientID == c.ID && q.Session == in.Session && active(q) {
			s.endLocked(q, "revoked", "CLI session ended")
		}
	}
	if err := s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) ownerRevoke(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Permanent bool `json:"permanent"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q := s.state.Requests[r.PathValue("id")]
	if q == nil {
		fail(w, 404, "Request not found")
		return
	}
	if active(q) {
		status := "revoked"
		if q.Status == "pending" && !in.Permanent {
			status = "denied"
		}
		s.endLocked(q, status, "Ended from your phone")
	}
	if err := s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 200, q)
}

func (s *Server) approveBegin(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canStartLocked(w) {
		return
	}
	q := s.state.Requests[r.PathValue("id")]
	if q == nil {
		fail(w, 404, "Request not found")
		return
	}
	s.checkExpiryLocked(q)
	if q.Mode == "connection" || (q.Status != "pending" && !(q.Mode == "persistent" && q.Status == "locked")) || q.Fingerprint != s.state.Owner.Fingerprint {
		fail(w, 409, "This request is no longer pending")
		return
	}
	l := s.live[q.ID]
	if l == nil {
		fail(w, 409, "Request no longer available")
		return
	}
	// Only one approval ceremony can own the ephemeral recipient for a request.
	for id, c := range s.ceremonies {
		if c.RequestID == q.ID {
			delete(s.ceremonies, id)
		}
	}
	if l.Worker != nil {
		l.Worker.Close()
		l.Worker = nil
	}
	deadline := time.Now().Add(time.Duration(q.DurationSeconds)*time.Second + 3*time.Minute)
	if q.Mode == "persistent" {
		deadline = time.Time{}
	}
	worker, err := signer.Start(s.config.Executable, q.ID, q.Fingerprint, deadline)
	if err != nil {
		s.errorInternal(w, err)
		return
	}
	l.Worker = worker
	opts, session, err := s.auth.BeginLogin(s.state.Owner, webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: s.state.Owner.Salt}), webauthn.WithExtensionLargeBlobRead()))
	if err != nil {
		worker.Close()
		l.Worker = nil
		s.errorInternal(w, err)
		return
	}
	id := s.addCeremonyLocked(ceremony{Kind: "approve", Session: session, Browser: s.browser(r), RequestID: q.ID})
	jsonReply(w, 200, map[string]any{"ceremony": id, "options": opts, "publicKey": worker.PublicKey, "request": q})
}
func (s *Server) approveFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ceremony   string          `json:"ceremony"`
		Credential json.RawMessage `json:"credential"`
		Envelope   signer.Envelope `json:"envelope"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.takeCeremonyLocked(in.Ceremony, "approve", s.browser(r))
	if err != nil || c.RequestID != r.PathValue("id") {
		fail(w, 400, "Approval expired or belongs to a different request")
		return
	}
	q := s.state.Requests[c.RequestID]
	l := s.live[c.RequestID]
	if q == nil || l == nil || l.Worker == nil {
		fail(w, 409, "Request no longer available")
		return
	}
	s.checkExpiryLocked(q)
	if q.Mode == "connection" || (q.Status != "pending" && !(q.Mode == "persistent" && q.Status == "locked")) || q.Fingerprint != s.state.Owner.Fingerprint {
		fail(w, 409, "Request no longer pending")
		return
	}
	if err = s.verifyLocked(c, in.Credential); err != nil {
		l.Worker.Close()
		l.Worker = nil
		fail(w, 401, "Passkey verification failed")
		return
	}
	expires := time.Now().Add(time.Duration(q.DurationSeconds) * time.Second)
	if q.Mode == "age-once" {
		expires = time.Now().Add(time.Minute)
	}
	if q.Mode == "persistent" {
		expires = time.Time{}
	}
	unlocked, err := l.Worker.Do(signer.Message{Action: "unlock", Access: q.Access, IdleSeconds: q.IdleSeconds, Envelope: &in.Envelope, ExpiresAt: expires})
	if err != nil {
		s.endLocked(q, "denied", "Key unlock failed")
		_ = s.persistLocked()
		message := "The key could not be unlocked"
		if access.AllowsAge(q.Access) {
			message += ". Age decryption requires an RSA or Ed25519 SSH key."
		}
		fail(w, 400, message)
		return
	}
	q.Status = "active"
	q.LastUsedAt = time.Now()
	q.EndReason = ""
	q.EndedAt = time.Time{}
	q.ExpiresAt = expires
	if q.Mode == "persistent" {
		for _, child := range s.state.Requests {
			if child.GrantID == q.ID && child.Status == "pending" {
				child.Status = "active"
				child.ExpiresAt = time.Now().Add(time.Duration(child.DurationSeconds) * time.Second)
			}
		}
	}
	if pub, parseErr := ssh.ParsePublicKey(unlocked.PublicKey); parseErr == nil && ssh.FingerprintSHA256(pub) == s.state.Owner.Fingerprint {
		s.state.Owner.PublicKey = string(ssh.MarshalAuthorizedKey(pub))
	}
	if err = s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 200, q)
}
func (s *Server) agentMessage(w http.ResponseWriter, r *http.Request) {
	var in signer.Message
	if !decode(w, r, &in) {
		return
	}
	if (in.Action != "list" && in.Action != "sign") || in.Access != "" || in.IdleSeconds != 0 || in.Envelope != nil || !in.ExpiresAt.IsZero() || len(in.Data) > 32768 {
		fail(w, 400, "Agent operation not permitted")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	q, _, ok := s.leaseLocked(r)
	if !ok {
		fail(w, 401, "Unknown request capability")
		return
	}
	s.checkExpiryLocked(q)
	if !access.AllowsSSH(q.Access) {
		fail(w, 403, "This lease does not allow SSH authentication")
		return
	}
	worker := s.workerLocked(q)
	if q.Mode == "persistent" || q.Status != "active" || worker == nil {
		fail(w, 403, "SSH grant is locked")
		return
	}
	reply, err := worker.Do(in)
	if err != nil {
		if q.GrantID != "" {
			s.endLocked(s.state.Requests[q.GrantID], "locked", "Signer stopped; unlock to resume")
		} else {
			s.endLocked(q, "revoked", "Signer stopped")
		}
		_ = s.persistLocked()
		fail(w, 403, "Signer is unavailable; grant closed")
		return
	}
	if q.GrantID != "" && in.Action == "sign" {
		s.state.Requests[q.GrantID].LastUsedAt = time.Now()
		if err := s.persistLocked(); err != nil {
			s.errorInternal(w, err)
			return
		}
	}
	// Hold the lifecycle lock through response emission. Revocation cannot return
	// while a new signing operation is still being dispatched.
	jsonReply(w, 200, reply)
}
