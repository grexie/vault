package app

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/grexie/remote-ssh-agent/internal/limits"
	"github.com/grexie/remote-ssh-agent/internal/signer"
)

// A job has its own short-lived capability and socket. It cannot unlock the
// parent, create other grants, or revoke other jobs using its child capability.
func (s *Server) grantConnect(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Session    string `json:"session"`
		Socket     string `json:"socket"`
		Duration   int    `json:"durationSeconds"`
		RequestKey []byte `json:"requestKey"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.RequestKey) != 32 || !SessionPattern.MatchString(in.Session) || !filepath.IsAbs(in.Socket) || !textValid(in.Socket, 1, 104) || in.Duration < 1 || in.Duration > int(limits.MaxLeaseDuration/time.Second) {
		fail(w, 400, "A session, local socket, and connection duration of 1s–48h are required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := r.PathValue("id")
	q := s.state.Requests[id]
	secret := s.state.Grants[id]
	if q == nil || q.Mode != "persistent" || secret.ConnectionHash == "" || !equalSecret(secret.ConnectionHash, tokenHash(bearer(r))) {
		fail(w, 401, "Invalid connection token")
		return
	}
	s.checkExpiryLocked(q)
	if q.Status == "active" && s.workerLocked(q) == nil {
		s.endLocked(q, "locked", "Signer stopped")
	}
	if q.Status != "active" && q.Status != "locked" && q.Status != "pending" {
		fail(w, 403, "Persistent grant is unavailable")
		return
	}
	if !s.canStartLocked(w) {
		return
	}
	n := 0
	for _, child := range s.state.Requests {
		if child.GrantID == id && active(child) {
			n++
		}
	}
	if n >= 32 {
		fail(w, 429, "Too many live connections for this grant")
		return
	}
	needsApproval := q.Status != "active"
	notify := q.Status == "locked"
	if notify {
		q.Status = "pending"
		q.PendingUntil = time.Now().Add(5 * time.Minute)
		q.Notification = "sending"
	}
	if !needsApproval {
		if _, err := s.workerLocked(q).Do(signer.Message{Action: "touch"}); err != nil {
			s.endLocked(q, "locked", "Signer stopped; connect again to request approval")
			_ = s.persistLocked()
			fail(w, 403, "Signer stopped; connect again to request approval")
			return
		}
		q.LastUsedAt = time.Now()
	}
	child := &Request{ID: randomToken(), ClientID: q.ClientID, ClientName: q.ClientName,
		Session: in.Session, Reason: q.Reason, Access: q.Access, Mode: "connection", GrantID: id,
		Socket: in.Socket, RequestKey: in.RequestKey, KeyName: q.KeyName, Fingerprint: q.Fingerprint, DurationSeconds: in.Duration,
		Status: "active", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Duration(in.Duration) * time.Second)}
	if needsApproval {
		child.Status = "pending"
		child.ExpiresAt = time.Time{}
		child.PendingUntil = q.PendingUntil
	}
	cap := randomToken()
	s.state.Requests[child.ID] = child
	s.live[child.ID] = &liveRequest{CapabilityHash: tokenHash(cap)}
	// Bound completed connection history even if no new approvals are requested.
	for key, old := range s.state.Requests {
		if len(s.state.Requests) <= 500 {
			break
		}
		if !active(old) && old.Mode == "connection" {
			delete(s.state.Requests, key)
			delete(s.live, key)
		}
	}
	if err := s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	if notify {
		go s.notify(q.ID)
	}
	jsonReply(w, 201, map[string]any{"request": child, "capability": cap})
}

func (s *Server) workerLocked(q *Request) *signer.Worker {
	if q.GrantID != "" {
		q = s.state.Requests[q.GrantID]
	}
	if q != nil {
		s.checkExpiryLocked(q)
	}
	if q == nil || q.Status != "active" || (!q.ExpiresAt.IsZero() && time.Now().After(q.ExpiresAt)) {
		return nil
	}
	if l := s.live[q.ID]; l != nil {
		return l.Worker
	}
	return nil
}

// Tokens contain only an origin, public grant ID and a revocable random secret.
// Keeping identifiers restricted also prevents constructing arbitrary API paths.
func ValidGrantID(id string) bool {
	return len(id) == 43 && !strings.ContainsAny(id, "/.\\") && len(strings.Trim(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")) == 0
}
