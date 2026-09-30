package cloud

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/vaultwire"
)

type deviceRecord struct {
	Device      vaultwire.DeviceDescriptor `json:"device"`
	PairingHash string                     `json:"pairingHash"`
	PairingBox  *vaultwire.Envelope        `json:"pairingBox,omitempty"`
	OwnerID     string                     `json:"ownerId"`
	CreatedAt   time.Time                  `json:"createdAt"`
	Revoked     bool                       `json:"revoked"`
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{24,64}$`)
var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type deviceHandler func(http.ResponseWriter, *http.Request, deviceRecord)

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/catalog", s.requireSession(s.putCatalog))
	mux.HandleFunc("POST /api/v1/device/catalog", s.withDevice(s.deviceCatalog))
	mux.HandleFunc("POST /api/v1/device/enroll", s.withDevice(s.enroll))
	mux.HandleFunc("POST /api/v1/device/pairing", s.withDevice(s.pairingStatus))
	mux.HandleFunc("POST /api/v1/device/requests", s.withDevice(s.submitRequest))
	mux.HandleFunc("POST /api/v1/device/requests/{id}", s.withDevice(s.deviceRequest))
	mux.HandleFunc("POST /api/v1/device/requests/{id}/revoke", s.withDevice(s.deviceRevoke))
	mux.HandleFunc("POST /api/v1/device/inbox", s.withDevice(s.deviceInbox))
	mux.HandleFunc("POST /api/v1/device/requests/{id}/receiver", s.withDevice(s.setReceiver))
	mux.HandleFunc("POST /api/v1/devices/pair", s.requireSession(s.pairDevice))
	mux.HandleFunc("POST /api/v1/devices/{id}/revoke", s.requireSession(s.revokeDevice))
	mux.HandleFunc("GET /api/v1/requests", s.requireSession(s.listRequests))
	mux.HandleFunc("POST /api/v1/requests/{id}/approve", s.requireSession(s.approveRequest))
	mux.HandleFunc("POST /api/v1/requests/{id}/complete", s.requireSession(s.completeRequest))
	mux.HandleFunc("POST /api/v1/requests/{id}/decline", s.requireSession(s.declineRequest))
	mux.HandleFunc("POST /api/v1/requests/{id}/revoke", s.requireSession(s.revokeRequest))
}
func (s *Server) withDevice(next deviceHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Cookie authentication is never accepted for the device API.
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			fail(w, 403, "Device proof required")
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 7*1024*1024))
		if e != nil {
			fail(w, 400, "Request too large")
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b))
		proofBytes, e := base64.RawURLEncoding.DecodeString(r.Header.Get("X-Vault-Proof"))
		var signed vaultwire.Signed
		var proof vaultwire.HTTPProof
		if e != nil || len(proofBytes) > 4096 || json.Unmarshal(proofBytes, &signed) != nil || json.Unmarshal(signed.Payload, &proof) != nil || !idPattern.MatchString(proof.DeviceID) {
			fail(w, 401, "Invalid device proof")
			return
		}
		var d deviceRecord
		if r.URL.Path == "/api/v1/device/enroll" {
			var en vaultwire.Enrollment
			if json.Unmarshal(b, &en) != nil || en.Device.ID != proof.DeviceID || vaultwire.ID(en.Device.PublicKey) != proof.DeviceID || !vaultwire.ValidPublic(en.Device.BoxPublic) {
				fail(w, 400, "Invalid device enrollment")
				return
			}
			d.Device = en.Device
		} else {
			if _, e = s.store.Get(r.Context(), "devices", proof.DeviceID, &d); e != nil || d.Revoked {
				fail(w, 401, "Device is not paired or was revoked")
				return
			}
		}
		if vaultwire.Verify(d.Device.PublicKey, "http", signed, &proof) != nil || proof.Method != r.Method || proof.Path != r.URL.RequestURI() || proof.BodyHash != vaultwire.Digest(b) || !idPattern.MatchString(proof.Nonce) || time.Since(proof.At) > time.Minute || time.Until(proof.At) > time.Minute {
			fail(w, 401, "Device proof rejected")
			return
		}
		if r.URL.Path == "/api/v1/device/enroll" && !s.allowIP(w, r, "enroll-ip", "Please wait before pairing again") {
			return
		}
		if r.URL.Path == "/api/v1/device/requests" && !s.allowKey("requests/"+d.Device.ID) {
			fail(w, 429, "Request limit reached; wait before trying again")
			return
		}
		until := time.Now().Add(3 * time.Minute)
		if s.store.Put(r.Context(), "replays", proof.DeviceID+":"+proof.Nonce, 0, true, &until) != nil {
			fail(w, 409, "Device proof already used")
			return
		}
		if r.URL.Path != "/api/v1/device/enroll" && r.URL.Path != "/api/v1/device/pairing" && d.OwnerID == "" {
			fail(w, 403, "Pair this device in Vault first")
			return
		}
		next(w, r, d)
	}
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	var in vaultwire.Enrollment
	if !decode(w, r, &in) {
		return
	}
	if in.Device.ID != d.Device.ID || len(in.PairingHash) != 64 || strings.TrimSpace(in.Device.Name) == "" || len(in.Device.Name) > 80 {
		fail(w, 400, "Invalid device enrollment")
		return
	}
	if in.Device.Role != "client" && in.Device.Role != "agent" {
		fail(w, 400, "Device role must be client or agent")
		return
	}
	d = deviceRecord{Device: in.Device, PairingHash: in.PairingHash, CreatedAt: time.Now()}
	expires := time.Now().Add(15 * time.Minute)
	if s.store.Put(r.Context(), "devices", d.Device.ID, 0, d, &expires) != nil {
		fail(w, 409, "Device enrollment already exists")
		return
	}
	reply(w, 201, map[string]bool{"ok": true})
}
func (s *Server) pairingStatus(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	reply(w, 200, map[string]any{"paired": d.OwnerID != "", "box": d.PairingBox})
}
func (s *Server) pairDevice(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var in struct {
		DeviceID     string             `json:"deviceId"`
		PairingHash  string             `json:"pairingHash"`
		Box          vaultwire.Envelope `json:"box"`
		Verification string             `json:"verification"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !s.consumeVerification(r, user.key(), "pair:"+in.DeviceID, in.Verification) {
		fail(w, 403, "Verify your passkey to pair this device")
		return
	}
	var d deviceRecord
	v, e := s.store.Get(r.Context(), "devices", in.DeviceID, &d)
	if e != nil || d.OwnerID != "" || d.PairingHash != in.PairingHash || !validBox(in.Box) {
		fail(w, 409, "Pairing code expired or already used")
		return
	}
	d.OwnerID = user.key()
	d.PairingHash = ""
	d.PairingBox = &in.Box
	if s.store.Put(r.Context(), "devices", d.Device.ID, v, d, nil) != nil {
		fail(w, 409, "Device changed; retry pairing")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func validBox(b vaultwire.Envelope) bool {
	return vaultwire.ValidPublic(b.PublicKey) && len(b.Salt) == 32 && len(b.IV) == 12 && len(b.Ciphertext) >= 16 && len(b.Ciphertext) <= 6*1024*1024
}
func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var d deviceRecord
	v, e := s.store.Get(r.Context(), "devices", r.PathValue("id"), &d)
	if e != nil || d.OwnerID != user.key() {
		fail(w, 404, "Device not found")
		return
	}
	d.Revoked = true
	d.PairingBox = nil
	if s.store.Put(r.Context(), "devices", d.Device.ID, v, d, nil) != nil {
		fail(w, 409, "Device changed; try again")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) submitRequest(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	var in struct {
		Signed   vaultwire.Signed  `json:"signed"`
		Receiver *vaultwire.Signed `json:"receiver,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	var q vaultwire.Request
	if vaultwire.Verify(d.Device.PublicKey, "request", in.Signed, &q) != nil || q.DeviceID != d.Device.ID || !idPattern.MatchString(q.ID) || !sessionPattern.MatchString(q.Session) || len(strings.TrimSpace(q.Reason)) < 8 || len(q.Reason) > 1000 || len(q.Identity) > 80 || q.Duration < 1 || q.Duration > 172800 || time.Since(q.CreatedAt) > time.Minute || time.Until(q.CreatedAt) > time.Minute || !time.Now().Before(q.ExpiresAt) || q.ExpiresAt.Sub(q.CreatedAt) > 15*time.Minute {
		fail(w, 400, "Invalid signed request or duration")
		return
	}
	switch q.Kind {
	case "create", "lookup", "import", "ssh", "age", "ethereum", "bitcoin", "hyperliquid", "wallet-connect", "wallet-sign", "credentials", "api", "autofill", "keychain-import":
	default:
		fail(w, 400, "Unsupported request type")
		return
	}
	if vaultwire.ValidateRequest(q) != nil {
		fail(w, 400, "Request operation and identity type do not match")
		return
	}
	var target deviceRecord
	if _, e := s.store.Get(r.Context(), "devices", q.AgentID, &target); e != nil || target.OwnerID != d.OwnerID || target.Revoked {
		fail(w, 403, "Agent must be paired to the same owner")
		return
	}
	if q.Managed && (target.Device.Role != "agent" || in.Receiver != nil) {
		fail(w, 403, "Managed signing requires a separately paired signing agent and its own receiver")
		return
	}
	if in.Receiver != nil && !validReceiver(target.Device.PublicKey, in.Receiver, q.ID, vaultwire.Digest(in.Signed.Payload)) {
		fail(w, 400, "Invalid agent receiver")
		return
	}
	s.admission.Lock()
	defer s.admission.Unlock()
	docs, err := s.store.List(r.Context(), "requests:"+d.OwnerID)
	if err != nil {
		fail(w, 503, "Request storage unavailable")
		return
	}
	active := 0
	for _, doc := range docs {
		var state vaultwire.RequestState
		if s.store.Open(doc, &state) == nil && (state.Status == "pending" || state.Status == "approved") {
			active++
		}
	}
	if active >= 64 {
		fail(w, 429, "Active request limit reached; revoke unused sessions")
		return
	}
	state := vaultwire.RequestState{ID: q.ID, OwnerID: d.OwnerID, DeviceID: d.Device.ID, AgentID: q.AgentID, Session: q.Session, Reason: q.Reason, Status: "pending", Signed: in.Signed, Receiver: in.Receiver, ExpiresAt: q.ExpiresAt, ApprovalDeadline: q.ExpiresAt}
	if s.store.Put(r.Context(), "requests:"+d.OwnerID, q.ID, 0, state, &state.ExpiresAt) != nil {
		fail(w, 409, "Request already exists")
		return
	}
	s.notifyRequest(d.OwnerID)
	reply(w, 201, state)
}
func validReceiver(pub []byte, signed *vaultwire.Signed, id, hash string) bool {
	if signed == nil {
		return false
	}
	var recv vaultwire.Receiver
	return vaultwire.Verify(pub, "receiver", *signed, &recv) == nil && recv.RequestID == id && recv.RequestHash == hash && vaultwire.ValidPublic(recv.PublicKey) && time.Now().Before(recv.ExpiresAt) && time.Until(recv.ExpiresAt) <= 49*time.Hour
}
func (s *Server) request(r *http.Request, owner string) (vaultwire.RequestState, int64, error) {
	var q vaultwire.RequestState
	v, e := s.store.Get(r.Context(), "requests:"+owner, r.PathValue("id"), &q)
	if e == nil && q.OwnerID != owner {
		e = cloudstore.ErrNotFound
	}
	return q, v, e
}
func (s *Server) participantsActive(r *http.Request, q vaultwire.RequestState) bool {
	for _, id := range []string{q.DeviceID, q.AgentID} {
		var d deviceRecord
		if _, e := s.store.Get(r.Context(), "devices", id, &d); e != nil || d.Revoked || d.OwnerID != q.OwnerID {
			return false
		}
	}
	return true
}
func (s *Server) deviceRequest(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	q, _, e := s.request(r, d.OwnerID)
	if e != nil || q.DeviceID != d.Device.ID && q.AgentID != d.Device.ID || !s.participantsActive(r, q) {
		fail(w, 404, "Request expired or not found")
		return
	}
	if q.AgentID != d.Device.ID {
		q.Box = nil
	}
	reply(w, 200, q)
}
func (s *Server) deviceRevoke(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	q, v, e := s.request(r, d.OwnerID)
	if e != nil || q.DeviceID != d.Device.ID && q.AgentID != d.Device.ID || !s.participantsActive(r, q) {
		fail(w, 404, "Request not found")
		return
	}
	s.setStatus(w, r, q, v, "revoked")
}
func (s *Server) setStatus(w http.ResponseWriter, r *http.Request, q vaultwire.RequestState, v int64, status string) {
	q.Status = status
	q.Box = nil
	q.Response = nil
	q.ExpiresAt = time.Now().Add(time.Hour)
	if s.store.Put(r.Context(), "requests:"+q.OwnerID, q.ID, v, q, &q.ExpiresAt) != nil {
		fail(w, 409, "Request changed; retry")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) deviceInbox(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	docs, e := s.store.List(r.Context(), "requests:"+d.OwnerID)
	if e != nil {
		fail(w, 503, "Inbox unavailable")
		return
	}
	out := []vaultwire.RequestState{}
	for _, doc := range docs {
		var q vaultwire.RequestState
		if s.store.Open(doc, &q) == nil && q.AgentID == d.Device.ID && (q.Status == "pending" || q.Status == "approved") && s.participantsActive(r, q) {
			out = append(out, q)
		}
	}
	reply(w, 200, map[string]any{"requests": out})
}
func (s *Server) setReceiver(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	var in struct {
		Receiver vaultwire.Signed `json:"receiver"`
	}
	if !decode(w, r, &in) {
		return
	}
	q, v, e := s.request(r, d.OwnerID)
	if e != nil || q.AgentID != d.Device.ID || q.Status != "pending" || q.Receiver != nil || !validReceiver(d.Device.PublicKey, &in.Receiver, q.ID, vaultwire.Digest(q.Signed.Payload)) {
		fail(w, 409, "Agent receiver cannot be changed")
		return
	}
	q.Receiver = &in.Receiver
	if s.store.Put(r.Context(), "requests:"+d.OwnerID, q.ID, v, q, &q.ExpiresAt) != nil {
		fail(w, 409, "Request changed")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) listRequests(w http.ResponseWriter, r *http.Request, session Session, user User) {
	docs, e := s.store.List(r.Context(), "requests:"+user.key())
	if e != nil {
		fail(w, 503, "Requests unavailable")
		return
	}
	out := []vaultwire.RequestState{}
	for _, doc := range docs {
		var q vaultwire.RequestState
		if s.store.Open(doc, &q) == nil && (q.Status == "pending" || q.Status == "approved") && s.participantsActive(r, q) {
			q.Box = nil
			q.Response = nil
			out = append(out, q)
		}
	}
	reply(w, 200, map[string]any{"requests": out})
}
func (s *Server) approveRequest(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var in struct {
		Box           vaultwire.Envelope `json:"box"`
		Verification  string             `json:"verification"`
		Authorization *vaultwire.Signed  `json:"authorization,omitempty"`
		VaultVersion  int64              `json:"vaultVersion"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.vaultMutation.Lock()
	defer s.vaultMutation.Unlock()
	if !s.requireVaultVersion(w, r, user, in.VaultVersion) {
		return
	}
	q, v, e := s.request(r, user.key())
	if e != nil || q.Status != "pending" || q.Receiver == nil || !validBox(in.Box) || !s.participantsActive(r, q) {
		fail(w, 409, "Request expired or unavailable")
		return
	}
	if !s.consumeVerification(r, user.key(), "approve:"+q.ID, in.Verification) {
		fail(w, 403, "Verify your passkey for this request")
		return
	}
	var spec vaultwire.Request
	json.Unmarshal(q.Signed.Payload, &spec)
	q.Box = &in.Box
	q.Authorization = in.Authorization
	q.Status = "approved"
	q.ExpiresAt = time.Now().Add(time.Duration(spec.Duration) * time.Second)
	if s.store.Put(r.Context(), "requests:"+user.key(), q.ID, v, q, &q.ExpiresAt) != nil {
		fail(w, 409, "Request changed")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) completeRequest(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var in struct {
		Response     vaultwire.Signed `json:"response"`
		Verification string           `json:"verification"`
		VaultVersion int64            `json:"vaultVersion"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.vaultMutation.Lock()
	defer s.vaultMutation.Unlock()
	if !s.requireVaultVersion(w, r, user, in.VaultVersion) {
		return
	}
	q, v, e := s.request(r, user.key())
	if e != nil || q.Status != "pending" || len(in.Response.Payload) > 1024*1024 || len(in.Response.Signature) != 64 {
		fail(w, 409, "Request expired or unavailable")
		return
	}
	var spec vaultwire.Request
	json.Unmarshal(q.Signed.Payload, &spec)
	if spec.Kind != "create" && spec.Kind != "import" && spec.Kind != "lookup" && spec.Kind != "keychain-import" && spec.Kind != "wallet-connect" {
		fail(w, 400, "Request requires an encrypted approval")
		return
	}
	if !s.consumeVerification(r, user.key(), "approve:"+q.ID, in.Verification) {
		fail(w, 403, "Verify your passkey for this request")
		return
	}
	q.Status = "completed"
	q.Response = &in.Response
	q.ExpiresAt = time.Now().Add(5 * time.Minute)
	if s.store.Put(r.Context(), "requests:"+user.key(), q.ID, v, q, &q.ExpiresAt) != nil {
		fail(w, 409, "Request changed")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) declineRequest(w http.ResponseWriter, r *http.Request, session Session, user User) {
	q, v, e := s.request(r, user.key())
	if e != nil || q.Status != "pending" {
		fail(w, 404, "Pending request not found")
		return
	}
	s.setStatus(w, r, q, v, "declined")
}
func (s *Server) revokeRequest(w http.ResponseWriter, r *http.Request, session Session, user User) {
	q, v, e := s.request(r, user.key())
	if e != nil {
		fail(w, 404, "Request not found")
		return
	}
	s.setStatus(w, r, q, v, "revoked")
}

type verification struct {
	UserID  string `json:"userId"`
	Purpose string `json:"purpose"`
	Used    bool   `json:"used"`
}

func (s *Server) consumeVerification(r *http.Request, user, purpose, ticket string) bool {
	if !idPattern.MatchString(ticket) {
		return false
	}
	var proof verification
	v, e := s.store.Get(r.Context(), "verifications", hash(ticket), &proof)
	if e != nil || proof.UserID != user || proof.Purpose != purpose || proof.Used {
		return false
	}
	proof.Used = true
	until := time.Now().Add(time.Minute)
	return s.store.Put(r.Context(), "verifications", hash(ticket), v, proof, &until) == nil
}
