package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/grexie/remote-ssh-agent/internal/proof"
	"github.com/grexie/remote-ssh-agent/internal/signer"
	"github.com/grexie/remote-ssh-agent/internal/vault"
	"github.com/grexie/remote-ssh-agent/web"
)

type Config struct {
	Origin, DataDir, Executable, Version string
	ResetSetup                           bool
}
type ceremony struct {
	Kind, Browser, RequestID, KeyName, Fingerprint string
	PublicKey                                      string
	Session                                        *webauthn.SessionData
	Owner                                          *Owner
	Expires                                        time.Time
}
type bodyDigestKey struct{}

type liveRequest struct {
	Nonces         map[string]time.Time
	CapabilityHash string
	Worker         *signer.Worker
}
type Server struct {
	mu         sync.Mutex
	config     Config
	store      *vault.Store
	state      State
	auth       *webauthn.WebAuthn
	ceremonies map[string]ceremony
	sessions   map[string]time.Time
	live       map[string]*liveRequest
	bootstrap  string
	closed     bool
	rateStart  time.Time
	rateCount  int
}

func ValidOrigin(origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("origin must be an absolute origin without a path")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return nil, errors.New("HTTPS is required except on loopback")
	}
	return u, nil
}

func New(cfg Config) (*Server, error) {
	u, err := ValidOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	cfg.Origin = strings.TrimSuffix(cfg.Origin, "/")
	if cfg.Executable == "" {
		cfg.Executable, err = os.Executable()
		if err != nil {
			return nil, err
		}
	}
	wa, err := webauthn.New(&webauthn.Config{RPDisplayName: "Remote SSH Agent", RPID: u.Hostname(), RPOrigins: []string{cfg.Origin}, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if err != nil {
		return nil, err
	}
	db, err := vault.Open(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{config: cfg, store: db, auth: wa, ceremonies: map[string]ceremony{}, sessions: map[string]time.Time{}, live: map[string]*liveRequest{}}
	if err = db.Load(&s.state); err != nil {
		db.Close()
		return nil, err
	}
	if s.state.Clients == nil {
		s.state.Clients = map[string]storedClient{}
	}
	if s.state.Requests == nil {
		s.state.Requests = map[string]*Request{}
	}
	if s.state.Grants == nil {
		s.state.Grants = map[string]grantSecrets{}
	}
	for id, secrets := range s.state.Grants {
		s.live[id] = &liveRequest{CapabilityHash: secrets.CapabilityHash}
	}
	for _, r := range s.state.Requests {
		if r.Mode == "persistent" && (r.Status == "active" || r.Status == "locked" || r.Status == "pending" && !r.LastUsedAt.IsZero()) {
			r.Status = "locked"
			r.EndReason = "Unlock this persistent grant after the server restart"
		} else if active(r) {
			r.Status = "revoked"
			r.EndedAt = time.Now()
			r.EndReason = "Server restarted"
		}
	}
	if s.state.VAPIDPrivate == "" {
		s.state.VAPIDPrivate, s.state.VAPIDPublic, err = webpush.GenerateVAPIDKeys()
		if err != nil {
			db.Close()
			return nil, err
		}
	}
	if s.state.Owner == nil {
		if s.state.BootstrapHash == "" || cfg.ResetSetup {
			s.bootstrap = randomToken()
			s.state.BootstrapHash = tokenHash(s.bootstrap)
			log.Printf("First setup at %s — one-time setup token: %s", cfg.Origin, s.bootstrap)
		} else {
			log.Printf("Owner setup is incomplete. Use the original setup token, or restart with --reset-setup.")
		}
	}
	if err = db.Save(&s.state); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	for _, r := range s.state.Requests {
		if active(r) {
			if r.Mode == "persistent" && (r.Status == "active" || r.Status == "locked" || r.Status == "pending" && !r.LastUsedAt.IsZero()) {
				s.endLocked(r, "locked", "Server stopped; unlock to resume")
			} else {
				s.endLocked(r, "revoked", "Server stopped")
			}
		}
	}
	e := s.store.Save(&s.state)
	c := s.store.Close()
	return errors.Join(e, c)
}

func (s *Server) RunJanitor(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				return
			}
			changed := false
			now := time.Now()
			for _, r := range s.state.Requests {
				if idleExpired(r, now) {
					s.endLocked(r, "locked", "Inactivity timeout; the next connection requests approval")
					changed = true
				} else if expired(r, now) {
					s.endLocked(r, "expired", "Time limit reached")
					changed = true
				}
			}
			for k, c := range s.ceremonies {
				if now.After(c.Expires) {
					delete(s.ceremonies, k)
					if c.Kind == "approve" {
						if l := s.live[c.RequestID]; l != nil && l.Worker != nil {
							l.Worker.Close()
							l.Worker = nil
						}
					}
				}
			}
			for k, e := range s.sessions {
				if now.After(e) {
					delete(s.sessions, k)
				}
			}
			if changed {
				_ = s.persistLocked()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) persistLocked() error {
	if err := s.store.Save(&s.state); err != nil {
		// Storage failures cannot leave an unrecorded grant usable.
		for _, r := range s.state.Requests {
			if active(r) {
				s.endLocked(r, "revoked", "Storage unavailable")
			}
		}
		log.Printf("metadata storage unavailable: %v", err)
		return errors.New("storage unavailable; grants were closed")
	}
	return nil
}

func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /api/info", s.info)
	m.HandleFunc("POST /api/setup/begin", s.setupBegin)
	m.HandleFunc("POST /api/setup/finish", s.setupFinish)
	m.HandleFunc("POST /api/auth/begin", s.loginBegin)
	m.HandleFunc("POST /api/auth/finish", s.loginFinish)
	m.HandleFunc("POST /api/logout", s.logout)
	m.HandleFunc("GET /api/state", s.owner(s.getState))
	m.HandleFunc("POST /api/key/{operation}/begin", s.owner(s.keyBegin))
	m.HandleFunc("POST /api/key/{operation}/finish", s.owner(s.keyFinish))
	m.HandleFunc("POST /api/clients", s.owner(s.addClient))
	m.HandleFunc("DELETE /api/clients/{id}", s.owner(s.removeClient))
	m.HandleFunc("POST /api/push", s.owner(s.subscribe))
	m.HandleFunc("POST /api/requests/{id}/approve/begin", s.owner(s.approveBegin))
	m.HandleFunc("POST /api/requests/{id}/approve/finish", s.owner(s.approveFinish))
	m.HandleFunc("POST /api/requests/{id}/revoke", s.owner(s.ownerRevoke))
	m.HandleFunc("POST /v1/requests", s.requestCreate)
	m.HandleFunc("GET /v1/recipient", s.ageRecipient)
	m.HandleFunc("POST /v1/grants/{id}/connect", s.grantConnect)
	m.HandleFunc("POST /v1/revoke", s.clientRevoke)
	m.HandleFunc("GET /v1/requests/{id}", s.requestStatus)
	m.HandleFunc("POST /v1/requests/{id}/agent", s.agentMessage)
	m.HandleFunc("POST /v1/requests/{id}/age", s.ageDecrypt)
	m.HandleFunc("POST /v1/requests/{id}/revoke", s.capabilityRevoke)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, map[string]any{"ok": true, "version": s.config.Version})
	})
	m.Handle("GET /", web.Handler())
	u, _ := url.Parse(s.config.Origin)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self), publickey-credentials-create=(self)")
		if u.Scheme == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.EqualFold(r.Host, u.Host) {
			fail(w, 403, "Unexpected host")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/v1/") {
			w.Header().Set("Cache-Control", "no-store")
			r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
			if strings.HasPrefix(r.URL.Path, "/v1/") && r.Header.Get("Origin") != "" {
				fail(w, 403, "CLI endpoints do not accept browser requests")
				return
			}
			if strings.HasPrefix(r.URL.Path, "/api/") && r.Method != "GET" && r.Header.Get("Origin") != s.config.Origin {
				fail(w, 403, "Origin check failed")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				fail(w, 400, "Invalid request body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r = r.WithContext(context.WithValue(r.Context(), bodyDigestKey{}, sha256.Sum256(body)))
		}
		m.ServeHTTP(w, r)
	})
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	jsonReply(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "Invalid request")
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		fail(w, 400, "Invalid request")
		return false
	}
	return true
}
func (s *Server) cookieName() string {
	if strings.HasPrefix(s.config.Origin, "https:") {
		return "__Host-rsa"
	}
	return "rsa-local"
}
func (s *Server) browser(r *http.Request) string {
	c, e := r.Cookie(s.cookieName())
	if e != nil {
		return ""
	}
	return tokenHash(c.Value)
}
func (s *Server) owner(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		expiry, ok := s.sessions[s.browser(r)]
		s.mu.Unlock()
		if !ok || time.Now().After(expiry) {
			jsonReply(w, 401, map[string]string{"error": "Sign in with your passkey", "code": "session_required"})
			return
		}
		h(w, r)
	}
}
func (s *Server) establish(w http.ResponseWriter) {
	t := randomToken()
	s.sessions[tokenHash(t)] = time.Now().Add(12 * time.Hour)
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: t, Path: "/", Secure: strings.HasPrefix(s.config.Origin, "https:"), HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	delete(s.sessions, s.browser(r))
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Path: "/", MaxAge: -1, HttpOnly: true, Secure: strings.HasPrefix(s.config.Origin, "https:"), SameSite: http.SameSiteStrictMode})
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jsonReply(w, 200, map[string]any{"registered": s.state.Owner != nil, "vapidPublicKey": s.state.VAPIDPublic})
}
func (s *Server) canStartLocked(w http.ResponseWriter) bool {
	if time.Since(s.rateStart) > time.Minute {
		s.rateStart = time.Now()
		s.rateCount = 0
	}
	s.rateCount++
	if s.rateCount > 60 || len(s.ceremonies) > 100 {
		fail(w, 429, "Too many attempts. Try again shortly.")
		return false
	}
	return true
}
func (s *Server) addCeremonyLocked(c ceremony) string {
	id := randomToken()
	c.Expires = time.Now().Add(2 * time.Minute)
	s.ceremonies[id] = c
	return id
}
func (s *Server) takeCeremonyLocked(id, kind, browser string) (ceremony, error) {
	c, ok := s.ceremonies[id]
	if !ok || c.Kind != kind || c.Browser != browser || time.Now().After(c.Expires) {
		return c, errors.New("ceremony expired or does not match")
	}
	delete(s.ceremonies, id)
	return c, nil
}
func bearer(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}
func equalSecret(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
func (s *Server) clientLocked(r *http.Request) (Client, bool) {
	h := tokenHash(bearer(r))
	for _, c := range s.state.Clients {
		if equalSecret(c.Hash, h) {
			return c.Client, true
		}
	}
	return Client{}, false
}
func (s *Server) leaseLocked(r *http.Request) (*Request, *liveRequest, bool) {
	id := r.PathValue("id")
	q := s.state.Requests[id]
	l := s.live[id]
	if q == nil || l == nil || !equalSecret(l.CapabilityHash, tokenHash(bearer(r))) {
		return nil, nil, false
	}
	digest, ok := r.Context().Value(bodyDigestKey{}).([32]byte)
	if !ok {
		return nil, nil, false
	}
	nonce, valid := proof.Verify(r, digest, q.RequestKey)
	if !valid {
		return nil, nil, false
	}
	if l.Nonces == nil {
		l.Nonces = map[string]time.Time{}
	}
	now := time.Now()
	for n, expiry := range l.Nonces {
		if now.After(expiry) {
			delete(l.Nonces, n)
		}
	}
	if _, seen := l.Nonces[nonce]; seen || len(l.Nonces) >= 4096 {
		return nil, nil, false
	}
	l.Nonces[nonce] = now.Add(2 * proof.Window)
	return q, l, true
}
func (s *Server) endLocked(r *Request, status, reason string) {
	if r.Mode == "persistent" && !r.LastUsedAt.IsZero() && (status == "denied" || status == "expired") {
		status = "locked"
	}
	r.Status = status
	if r.Mode == "persistent" {
		for _, child := range s.state.Requests {
			if child.GrantID == r.ID && active(child) {
				childStatus := "revoked"
				if child.Status == "pending" {
					childStatus = "denied"
				}
				s.endLocked(child, childStatus, reason)
			}
		}
		if status != "locked" {
			secrets := s.state.Grants[r.ID]
			secrets.ConnectionHash = ""
			s.state.Grants[r.ID] = secrets
		}
	}
	if l := s.live[r.ID]; l != nil && l.Worker != nil {
		l.Worker.Close()
		l.Worker = nil
	}
	r.Status = status
	r.EndedAt = time.Now()
	r.EndReason = reason
	if r.GrantID != "" {
		parent := s.state.Requests[r.GrantID]
		if parent != nil && parent.Status == "pending" {
			waiting := false
			for _, child := range s.state.Requests {
				if child.GrantID == parent.ID && child.Status == "pending" {
					waiting = true
					break
				}
			}
			if !waiting {
				s.endLocked(parent, "locked", "Waiting connection cancelled")
			}
		}
	}
}
func (s *Server) checkExpiryLocked(r *Request) {
	if idleExpired(r, time.Now()) {
		s.endLocked(r, "locked", "Inactivity timeout; the next connection requests approval")
		_ = s.persistLocked()
	} else if expired(r, time.Now()) {
		s.endLocked(r, "expired", "Time limit reached")
		_ = s.persistLocked()
	}
}
func (s *Server) getState(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clients := []Client{}
	for _, c := range s.state.Clients {
		clients = append(clients, c.Client)
	}
	jsonReply(w, 200, map[string]any{"key": map[string]any{"name": s.state.Owner.KeyName, "fingerprint": s.state.Owner.Fingerprint}, "requests": s.state.Requests, "clients": clients, "pushSubscriptions": len(s.state.Push), "vapidPublicKey": s.state.VAPIDPublic})
}

func (s *Server) errorInternal(w http.ResponseWriter, err error) {
	log.Printf("operation failed: %v", err)
	fail(w, 500, "The operation could not be completed")
}
