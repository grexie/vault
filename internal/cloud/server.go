// Package cloud is the hosted account, ciphertext storage and relay service.
// This package has no dependency on device-side private-key signers.
package cloud

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/grexie/vault/internal/cloudstore"
)

type Config struct {
	Origin, Version   string
	Development       bool
	TrustedProxyCIDRs []string
}
type Server struct {
	cfg           Config
	store         *cloudstore.Store
	auth          *webauthn.WebAuthn
	handler       http.Handler
	salt          []byte
	cookie        string
	mu            sync.Mutex
	rates         map[string]rate
	proxies       []netip.Prefix
	admission     sync.Mutex
	vaultMutation sync.Mutex // Serialize encrypted vault changes with approvals in this single-replica service.
	notifications chan struct{}
	notified      map[string]time.Time
}
type rate struct {
	Start time.Time
	N     int
}
type User struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	Credentials []webauthn.Credential `json:"credentials"`
	CreatedAt   time.Time             `json:"createdAt"`
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (u *User) key() string                                { return base64.RawURLEncoding.EncodeToString(u.ID) }

type Session struct {
	UserID    string    `json:"userId"`
	Wrap      []byte    `json:"wrap"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type Blob struct {
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}
type VaultRecord struct {
	WrappedKey Blob   `json:"wrappedKey"`
	Data       Blob   `json:"data"`
	Credential string `json:"credential"`
}

func (b Blob) valid(max int) bool {
	return len(b.IV) == 12 && len(b.Ciphertext) >= 16 && len(b.Ciphertext) <= max
}
func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func token() string        { return base64.RawURLEncoding.EncodeToString(random(32)) }
func hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024*1024))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		fail(w, 400, "Invalid request")
		return false
	}
	return true
}
func New(ctx context.Context, cfg Config, store *cloudstore.Store, assets http.Handler) (*Server, error) {
	proxies, err := trustedProxies(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.Origin)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, errors.New("an HTTPS origin without a path is required")
	}
	local := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()
	if u.Scheme != "https" && !(cfg.Development && local && u.Scheme == "http") {
		return nil, errors.New("HTTPS is required")
	}
	auth, err := webauthn.New(&webauthn.Config{RPDisplayName: "Grexie Vault", RPID: u.Hostname(), RPOrigins: []string{cfg.Origin}, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, proxies: proxies, store: store, auth: auth, cookie: "__Host-vault-session", rates: map[string]rate{}, notifications: make(chan struct{}, 8), notified: map[string]time.Time{}}
	if cfg.Development && u.Scheme == "http" {
		s.cookie = "vault-dev-session"
	}
	var conf struct {
		Salt []byte `json:"salt"`
	}
	_, err = store.Get(ctx, "configuration", "authentication", &conf)
	if errors.Is(err, cloudstore.ErrNotFound) {
		conf.Salt = random(32)
		err = store.Put(ctx, "configuration", "authentication", 0, conf, nil)
		if errors.Is(err, cloudstore.ErrConflict) {
			_, err = store.Get(ctx, "configuration", "authentication", &conf)
		}
	}
	if err != nil || len(conf.Salt) != 32 {
		return nil, errors.New("cannot load persistent authentication configuration")
	}
	s.salt = conf.Salt
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"ok": true, "version": cfg.Version, "service": "grexie-vault"})
	})
	mux.HandleFunc("POST /api/v1/auth/register/begin", s.registerBegin)
	mux.HandleFunc("POST /api/v1/auth/register/finish", s.registerFinish)
	mux.HandleFunc("POST /api/v1/auth/login/begin", s.loginBegin)
	mux.HandleFunc("POST /api/v1/auth/login/finish", s.loginFinish)
	mux.HandleFunc("POST /api/v1/auth/unlock/begin", s.requireSession(s.unlockBegin))
	mux.HandleFunc("POST /api/v1/auth/unlock/finish", s.requireSession(s.unlockFinish))
	mux.HandleFunc("GET /api/v1/session", s.requireSession(s.sessionInfo))
	mux.HandleFunc("POST /api/v1/session/wrapping-key", s.requireSession(s.wrappingKey))
	mux.HandleFunc("POST /api/v1/logout", s.requireSession(s.logout))
	mux.HandleFunc("GET /api/v1/vault", s.requireSession(s.getVault))
	mux.HandleFunc("PUT /api/v1/vault", s.requireSession(s.putVault))
	s.routes(mux)
	if err := s.pushRoutes(ctx, mux); err != nil {
		return nil, err
	}
	if assets != nil {
		mux.Handle("/", assets)
	}
	s.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://sourcify.dev; worker-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
		if strings.HasPrefix(cfg.Origin, "https:") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if r.Method != "GET" && !strings.HasPrefix(r.URL.Path, "/api/v1/device/") && (r.Header.Get("Origin") != cfg.Origin || r.Header.Get("Sec-Fetch-Site") == "cross-site") {
				fail(w, 403, "Same-origin request required")
				return
			}
			if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v1/auth/") && !s.allowIP(w, r, "auth-ip", "Please wait before trying again") {
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
	return s, nil
}
func (s *Server) Handler() http.Handler { return s.handler }

const maxRateKeys = 10000

func (s *Server) allowKey(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	r, exists := s.rates[key]
	if !exists && len(s.rates) >= maxRateKeys {
		for k, v := range s.rates {
			if now.Sub(v.Start) > time.Minute {
				delete(s.rates, k)
			}
		}
		if len(s.rates) >= maxRateKeys {
			return false
		}
	}
	if now.Sub(r.Start) > time.Minute {
		r = rate{Start: now}
	}
	if r.N >= 30 {
		return false
	}
	r.N++
	s.rates[key] = r
	return true
}

type sessionHandler func(http.ResponseWriter, *http.Request, Session, User)

func (s *Server) requireSession(next sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.cookie)
		if err != nil || len(c.Value) != 43 {
			fail(w, 401, "Sign in with a passkey")
			return
		}
		var session Session
		_, err = s.store.Get(r.Context(), "sessions", hash(c.Value), &session)
		if err != nil || !time.Now().Before(session.ExpiresAt) || len(session.Wrap) != 32 {
			fail(w, 401, "Sign in with a passkey")
			return
		}
		var user User
		if _, err = s.store.Get(r.Context(), "users", session.UserID, &user); err != nil {
			fail(w, 401, "Sign in with a passkey")
			return
		}
		next(w, r, session, user)
	}
}
func (s *Server) setCookie(w http.ResponseWriter, value string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookie, Value: value, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.cfg.Origin, "https:"), SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: maxAge})
}
func (s *Server) establish(w http.ResponseWriter, r *http.Request, u User) error {
	value := token()
	session := Session{UserID: u.key(), Wrap: random(32), CreatedAt: time.Now(), ExpiresAt: time.Now().Add(30 * 24 * time.Hour)}
	if err := s.store.Put(r.Context(), "sessions", hash(value), 0, session, &session.ExpiresAt); err != nil {
		return err
	}
	// A fresh login rotates the current browser session without affecting other devices.
	if old, err := r.Cookie(s.cookie); err == nil {
		_ = s.store.Delete(r.Context(), "sessions", hash(old.Value))
	}
	s.setCookie(w, value, session.ExpiresAt)
	return nil
}
func (s *Server) sessionInfo(w http.ResponseWriter, r *http.Request, session Session, u User) {
	reply(w, 200, map[string]any{"userId": u.key(), "name": u.Name, "expiresAt": session.ExpiresAt, "prfSalt": s.salt})
}
func (s *Server) wrappingKey(w http.ResponseWriter, r *http.Request, session Session, u User) {
	reply(w, 200, map[string]any{"key": session.Wrap, "context": "grexie-vault/session/v1:" + u.key() + ":" + session.CreatedAt.UTC().Format(time.RFC3339Nano), "expiresAt": session.ExpiresAt})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request, session Session, u User) {
	c, _ := r.Cookie(s.cookie)
	if s.store.Delete(r.Context(), "sessions", hash(c.Value)) != nil {
		fail(w, 503, "Could not sign out; retry")
		return
	}
	s.setCookie(w, "", time.Unix(1, 0))
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) getVault(w http.ResponseWriter, r *http.Request, session Session, u User) {
	var v VaultRecord
	version, err := s.store.Get(r.Context(), "vaults", u.key(), &v)
	if errors.Is(err, cloudstore.ErrNotFound) {
		reply(w, 200, map[string]any{"version": 0, "vault": nil})
		return
	}
	if err != nil {
		fail(w, 503, "Encrypted storage unavailable")
		return
	}
	reply(w, 200, map[string]any{"version": version, "vault": v})
}
func (s *Server) putVault(w http.ResponseWriter, r *http.Request, session Session, u User) {
	var in struct {
		Version          int64                `json:"version"`
		Vault            VaultRecord          `json:"vault"`
		RevokeIdentities []identityRevocation `json:"revokeIdentities,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Version < 0 || !in.Vault.WrappedKey.valid(32768) || !in.Vault.Data.valid(6*1024*1024) {
		fail(w, 400, "An encrypted vault and wrapped key are required")
		return
	}
	validCredential := false
	for _, cred := range u.Credentials {
		if base64.RawURLEncoding.EncodeToString(cred.ID) == in.Vault.Credential {
			validCredential = true
		}
	}
	if !validCredential {
		fail(w, 400, "Vault must be bound to an enrolled passkey")
		return
	}
	if !validRevocations(in.RevokeIdentities) {
		fail(w, 400, "Invalid identity deletion")
		return
	}
	s.vaultMutation.Lock()
	defer s.vaultMutation.Unlock()
	if !s.requireVaultVersion(w, r, u, in.Version) {
		return
	}
	if err := s.revokeIdentityRequests(r, u, in.RevokeIdentities); err != nil {
		fail(w, 503, "Could not revoke identity access; the identity has not been deleted. Try again.")
		return
	}
	err := s.store.Put(r.Context(), "vaults", u.key(), in.Version, in.Vault, nil)
	if errors.Is(err, cloudstore.ErrConflict) {
		fail(w, 409, "Your vault changed on another device. Reload before saving.")
		return
	}
	if err != nil {
		fail(w, 503, "Could not save encrypted vault")
		return
	}
	reply(w, 200, map[string]any{"version": in.Version + 1})
}
