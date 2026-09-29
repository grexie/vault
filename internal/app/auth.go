package app

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type finishInput struct {
	Ceremony   string          `json:"ceremony"`
	Credential json.RawMessage `json:"credential"`
}

func (s *Server) setupBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canStartLocked(w) {
		return
	}
	if s.state.Owner != nil || s.state.BootstrapHash == "" || !equalSecret(tokenHash(in.Token), s.state.BootstrapHash) {
		fail(w, 403, "Invalid setup token or setup is already complete")
		return
	}
	o := &Owner{ID: make([]byte, 32), Salt: make([]byte, 32)}
	_, _ = rand.Read(o.ID)
	_, _ = rand.Read(o.Salt)
	opts, session, err := s.auth.BeginRegistration(o, webauthn.WithExtensions(webauthn.WithExtensionPRFSupport(), webauthn.WithExtensionLargeBlobSupport(protocol.LargeBlobSupportRequired)))
	if err != nil {
		s.errorInternal(w, err)
		return
	}
	id := s.addCeremonyLocked(ceremony{Kind: "setup", Owner: o, Session: session})
	jsonReply(w, 200, map[string]any{"ceremony": id, "options": opts})
}
func credentialRequest(raw []byte) *http.Request {
	r, _ := http.NewRequest("POST", "https://local.invalid", bytes.NewReader(raw))
	return r
}
func (s *Server) setupFinish(w http.ResponseWriter, r *http.Request) {
	var in finishInput
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.takeCeremonyLocked(in.Ceremony, "setup", "")
	if err != nil || s.state.Owner != nil {
		fail(w, 400, "Setup ceremony expired")
		return
	}
	cred, err := s.auth.FinishRegistration(c.Owner, *c.Session, credentialRequest(in.Credential))
	if err != nil {
		fail(w, 400, "Passkey verification failed")
		return
	}
	if cred.Extensions.PRFEnabled == nil || !*cred.Extensions.PRFEnabled || cred.Extensions.LargeBlobSupported == nil || !*cred.Extensions.LargeBlobSupported {
		fail(w, 400, "This passkey provider must support both PRF and largeBlob")
		return
	}
	c.Owner.Credential = *cred
	s.state.Owner = c.Owner
	if err = s.persistLocked(); err != nil {
		s.state.Owner = nil
		s.errorInternal(w, err)
		return
	}
	s.bootstrap = ""
	s.state.BootstrapHash = ""
	if err = s.persistLocked(); err != nil {
		s.errorInternal(w, err)
		return
	}
	s.establish(w)
	jsonReply(w, 200, map[string]bool{"ok": true})
}

func (s *Server) loginBegin(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canStartLocked(w) {
		return
	}
	if s.state.Owner == nil {
		fail(w, 409, "Complete setup first")
		return
	}
	opts, session, err := s.auth.BeginLogin(s.state.Owner)
	if err != nil {
		s.errorInternal(w, err)
		return
	}
	jsonReply(w, 200, map[string]any{"ceremony": s.addCeremonyLocked(ceremony{Kind: "login", Session: session}), "options": opts})
}
func (s *Server) verifyLocked(c ceremony, raw []byte) error {
	cred, err := s.auth.FinishLogin(s.state.Owner, *c.Session, credentialRequest(raw))
	if err != nil {
		// Protocol errors describe the failed check; never log the credential
		// response, keychain blob, PRF output, or library debug information.
		log.Printf("passkey verification rejected: ceremony=%s detail=%q", c.Kind, err.Error())
		return err
	}
	if cred.Authenticator.CloneWarning {
		log.Printf("passkey verification rejected: ceremony=%s detail=authenticator-counter-rollback", c.Kind)
		return errors.New("authenticator counter rollback")
	}
	s.state.Owner.Credential = *cred
	return s.persistLocked()
}
func (s *Server) loginFinish(w http.ResponseWriter, r *http.Request) {
	var in finishInput
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.takeCeremonyLocked(in.Ceremony, "login", "")
	if err != nil {
		fail(w, 400, "Sign-in expired")
		return
	}
	if err = s.verifyLocked(c, in.Credential); err != nil {
		fail(w, 401, "Passkey verification failed")
		return
	}
	s.establish(w)
	jsonReply(w, 200, map[string]bool{"ok": true})
}

func (s *Server) keyBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
	}
	if !decode(w, r, &in) {
		return
	}
	op := r.PathValue("operation")
	if op != "read" && op != "write" {
		fail(w, 404, "Unknown key operation")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.canStartLocked(w) {
		return
	}
	ext := []webauthn.ExtensionOption{webauthn.WithExtensionPRF(protocol.PRFValues{First: s.state.Owner.Salt})}
	if op == "read" {
		ext = append(ext, webauthn.WithExtensionLargeBlobRead())
	} else {
		if len(strings.TrimSpace(in.Name)) == 0 || len(in.Name) > 80 || !validFingerprint(in.Fingerprint) {
			fail(w, 400, "A key name and SHA256 fingerprint are required")
			return
		}
		// Only a placeholder is sent. The browser substitutes its local ciphertext;
		// neither the blob nor PRF outputs are ever submitted to this server.
		ext = append(ext, webauthn.WithExtensionLargeBlobWrite([]byte{0}))
	}
	opts, session, err := s.auth.BeginLogin(s.state.Owner, webauthn.WithAssertionExtensions(ext...))
	if err != nil {
		s.errorInternal(w, err)
		return
	}
	id := s.addCeremonyLocked(ceremony{Kind: "key-" + op, Session: session, Browser: s.browser(r), KeyName: in.Name, Fingerprint: in.Fingerprint})
	jsonReply(w, 200, map[string]any{"ceremony": id, "options": opts, "salt": s.state.Owner.Salt})
}
func (s *Server) keyFinish(w http.ResponseWriter, r *http.Request) {
	var in finishInput
	if !decode(w, r, &in) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	op := r.PathValue("operation")
	c, err := s.takeCeremonyLocked(in.Ceremony, "key-"+op, s.browser(r))
	if err != nil {
		fail(w, 400, "Key operation expired")
		return
	}
	if err = s.verifyLocked(c, in.Credential); err != nil {
		fail(w, 401, "Passkey verification failed")
		return
	}
	if op == "write" {
		for _, q := range s.state.Requests {
			if active(q) {
				s.endLocked(q, "revoked", "SSH key replaced")
			}
		}
		s.state.Owner.KeyName = c.KeyName
		s.state.Owner.Fingerprint = c.Fingerprint
		if err = s.persistLocked(); err != nil {
			s.errorInternal(w, err)
			return
		}
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}
