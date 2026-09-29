package app

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Owner struct {
	ID          []byte              `json:"id"`
	Credential  webauthn.Credential `json:"credential"`
	Salt        []byte              `json:"salt"`
	KeyName     string              `json:"keyName"`
	Fingerprint string              `json:"fingerprint"`
}

func (o Owner) WebAuthnID() []byte          { return o.ID }
func (o Owner) WebAuthnName() string        { return "owner" }
func (o Owner) WebAuthnDisplayName() string { return "Remote SSH Agent" }
func (o Owner) WebAuthnCredentials() []webauthn.Credential {
	if len(o.Credential.ID) == 0 {
		return nil
	}
	return []webauthn.Credential{o.Credential}
}

type Client struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}
type storedClient struct {
	Client
	Hash string `json:"hash"`
}

type Request struct {
	ID              string    `json:"id"`
	ClientID        string    `json:"clientId"`
	ClientName      string    `json:"clientName"`
	Session         string    `json:"session"`
	Reason          string    `json:"reason"`
	Socket          string    `json:"socket"`
	KeyName         string    `json:"keyName"`
	Fingerprint     string    `json:"fingerprint"`
	DurationSeconds int       `json:"durationSeconds"`
	Status          string    `json:"status"`
	CreatedAt       time.Time `json:"createdAt"`
	PendingUntil    time.Time `json:"pendingUntil"`
	ExpiresAt       time.Time `json:"expiresAt,omitempty"`
	EndedAt         time.Time `json:"endedAt,omitempty"`
	EndReason       string    `json:"endReason,omitempty"`
	Notification    string    `json:"notification,omitempty"`
}

type State struct {
	BootstrapHash string                  `json:"bootstrapHash,omitempty"`
	Owner         *Owner                  `json:"owner"`
	Clients       map[string]storedClient `json:"clients"`
	Requests      map[string]*Request     `json:"requests"`
	Push          []webpush.Subscription  `json:"push"`
	VAPIDPublic   string                  `json:"vapidPublic"`
	VAPIDPrivate  string                  `json:"vapidPrivate"`
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func tokenHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func active(r *Request) bool { return r.Status == "pending" || r.Status == "active" }
