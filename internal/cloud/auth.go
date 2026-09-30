package cloud

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type ceremony struct {
	Kind      string               `json:"kind"`
	User      *User                `json:"user,omitempty"`
	UserID    string               `json:"userId,omitempty"`
	Session   webauthn.SessionData `json:"session"`
	Browser   string               `json:"browser"`
	ExpiresAt time.Time            `json:"expiresAt"`
	Used      bool                 `json:"used"`
	Purpose   string               `json:"purpose,omitempty"`
}
type finishInput struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

func credentialRequest(raw []byte) *http.Request {
	r, _ := http.NewRequest("POST", "https://local.invalid", bytes.NewReader(raw))
	return r
}
func (s *Server) saveCeremony(w http.ResponseWriter, r *http.Request, kind string, user *User, session *webauthn.SessionData, options any, purpose ...string) {
	browser := token()
	id := token()
	c := ceremony{Kind: kind, User: user, Session: *session, Browser: hash(browser), ExpiresAt: time.Now().Add(5 * time.Minute)}
	if len(purpose) > 0 {
		c.Purpose = purpose[0]
	}
	if user != nil {
		c.UserID = user.key()
	}
	if s.store.Put(r.Context(), "ceremonies", hash(id), 0, c, &c.ExpiresAt) != nil {
		fail(w, 503, "Unable to begin passkey verification")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookie + "-ceremony", Value: browser, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(s.cfg.Origin, "https:"), SameSite: http.SameSiteStrictMode, MaxAge: 300})
	reply(w, 200, map[string]any{"ceremony": id, "options": options, "prfSalt": s.salt})
}
func (s *Server) takeCeremony(r *http.Request, id, kind, userID string) (ceremony, error) {
	var c ceremony
	cookie, err := r.Cookie(s.cookie + "-ceremony")
	if err != nil {
		return c, errors.New("ceremony cookie required")
	}
	v, err := s.store.Get(r.Context(), "ceremonies", hash(id), &c)
	if err != nil || c.Used || c.Kind != kind || c.UserID != userID || c.Browser != hash(cookie.Value) || !time.Now().Before(c.ExpiresAt) {
		return c, errors.New("ceremony expired")
	}
	c.Used = true
	err = s.store.Put(r.Context(), "ceremonies", hash(id), v, c, &c.ExpiresAt)
	return c, err
}
func (s *Server) registerBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if len(name) < 1 || len(name) > 80 {
		fail(w, 400, "Enter an account name (1–80 characters)")
		return
	}
	user := &User{ID: random(32), Name: name, CreatedAt: time.Now()}
	options, session, err := s.auth.BeginRegistration(user, webauthn.WithExtensions(webauthn.WithExtensionPRFSupport()))
	if err != nil {
		fail(w, 500, "Unable to create a passkey")
		return
	}
	s.saveCeremony(w, r, "register", user, session, options)
}
func (s *Server) registerFinish(w http.ResponseWriter, r *http.Request) {
	var in finishInput
	if !decode(w, r, &in) {
		return
	}
	// Registration user is carried in the encrypted ceremony; it is not supplied
	// by a client-selected user ID.
	var stored ceremony
	if _, err := s.store.Get(r.Context(), "ceremonies", hash(in.Ceremony), &stored); err != nil || stored.User == nil {
		fail(w, 400, "Registration expired")
		return
	}
	c, err := s.takeCeremony(r, in.Ceremony, "register", stored.User.key())
	if err != nil {
		fail(w, 400, "Registration expired")
		return
	}
	cred, err := s.auth.FinishRegistration(c.User, c.Session, credentialRequest(in.Credential))
	if err != nil || cred == nil || cred.Extensions.PRFEnabled == nil || !*cred.Extensions.PRFEnabled {
		fail(w, 400, "This passkey must support PRF encryption. Choose a supported device keychain.")
		return
	}
	c.User.Credentials = []webauthn.Credential{*cred}
	if s.store.Put(r.Context(), "users", c.User.key(), 0, c.User, nil) != nil {
		fail(w, 503, "Could not save account")
		return
	}
	if err = s.establish(w, r, *c.User); err != nil {
		fail(w, 503, "Could not establish session")
		return
	}
	reply(w, 200, map[string]any{"userId": c.User.key(), "name": c.User.Name})
}
func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	options, session, err := s.auth.BeginDiscoverableLogin(webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: s.salt})))
	if err != nil {
		fail(w, 500, "Unable to begin sign in")
		return
	}
	s.saveCeremony(w, r, "login", nil, session, options)
}
func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request) {
	var in finishInput
	if !decode(w, r, &in) {
		return
	}
	c, err := s.takeCeremony(r, in.Ceremony, "login", "")
	if err != nil {
		fail(w, 400, "Sign in expired")
		return
	}
	var user User
	var version int64
	cred, err := s.auth.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
		var e error
		version, e = s.store.Get(r.Context(), "users", base64.RawURLEncoding.EncodeToString(userHandle), &user)
		return &user, e
	}, c.Session, credentialRequest(in.Credential))
	if err != nil || cred == nil || cred.Authenticator.CloneWarning {
		fail(w, 401, "Passkey verification failed")
		return
	}
	for i := range user.Credentials {
		if bytes.Equal(user.Credentials[i].ID, cred.ID) {
			user.Credentials[i] = *cred
		}
	}
	if s.store.Put(r.Context(), "users", user.key(), version, user, nil) != nil {
		fail(w, 409, "Account changed; please sign in again")
		return
	}
	if s.establish(w, r, user) != nil {
		fail(w, 503, "Could not establish session")
		return
	}
	reply(w, 200, map[string]any{"userId": user.key(), "name": user.Name})
}
func (s *Server) unlockBegin(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var in struct {
		Purpose string `json:"purpose"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Purpose) > 100 {
		fail(w, 400, "Invalid verification purpose")
		return
	}
	options, data, err := s.auth.BeginLogin(&user, webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: s.salt})))
	if err != nil {
		fail(w, 500, "Unable to begin unlock")
		return
	}
	s.saveCeremony(w, r, "unlock", &user, data, options, in.Purpose)
}
func (s *Server) unlockFinish(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var in finishInput
	if !decode(w, r, &in) {
		return
	}
	c, err := s.takeCeremony(r, in.Ceremony, "unlock", user.key())
	if err != nil {
		fail(w, 400, "Unlock expired")
		return
	}
	var current User
	version, err := s.store.Get(r.Context(), "users", user.key(), &current)
	if err != nil {
		fail(w, 503, "Account unavailable")
		return
	}
	cred, err := s.auth.FinishLogin(&current, c.Session, credentialRequest(in.Credential))
	if err != nil || cred == nil || cred.Authenticator.CloneWarning {
		fail(w, 403, "Passkey verification failed")
		return
	}
	for i := range current.Credentials {
		if bytes.Equal(current.Credentials[i].ID, cred.ID) {
			current.Credentials[i] = *cred
		}
	}
	if s.store.Put(r.Context(), "users", current.key(), version, current, nil) != nil {
		fail(w, 409, "Account changed; try again")
		return
	}
	ticket := token()
	expires := time.Now().Add(2 * time.Minute)
	if s.store.Put(r.Context(), "verifications", hash(ticket), 0, verification{UserID: user.key(), Purpose: c.Purpose}, &expires) != nil {
		fail(w, 503, "Unable to save verification")
		return
	}
	reply(w, 200, map[string]any{"ok": true, "verification": ticket})
}
