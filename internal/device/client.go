// Package device runs on a user-controlled machine. The hosted relay never
// imports this package and never possesses its private keys or decrypted grants.
package device

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/vaultwire"
)

type Config struct {
	AgentID         string                     `json:"agentId,omitempty"`
	AgentURL        string                     `json:"agentUrl,omitempty"`
	Version         int                        `json:"version"`
	Server          string                     `json:"server"`
	Device          vaultwire.DeviceDescriptor `json:"device"`
	PrivateKey      []byte                     `json:"privateKey"`
	BoxPrivate      []byte                     `json:"boxPrivate"`
	PairingSecret   []byte                     `json:"pairingSecret,omitempty"`
	OwnerID         string                     `json:"ownerId"`
	OwnerPublic     []byte                     `json:"ownerPublic"`
	OwnerBoxPublic  []byte                     `json:"ownerBoxPublic"`
	DefaultIdentity string                     `json:"defaultIdentity,omitempty"`
}

func DefaultConfig() string {
	p, e := os.UserConfigDir()
	if e != nil {
		p = "."
	}
	return filepath.Join(p, "grexie-vault", "config.json")
}
func RandomID() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func ValidateServer(server string) error {
	u, e := url.Parse(server)
	if e != nil || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("server must be an HTTPS origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback())) {
		return errors.New("HTTPS is required except on literal loopback test addresses")
	}
	return nil
}
func NewConfig(server, name string) (Config, error) {
	var c Config
	if e := ValidateServer(server); e != nil {
		return c, e
	}
	if strings.TrimSpace(name) == "" || len(name) > 80 {
		return c, errors.New("device name is required")
	}
	key, e := vaultwire.NewKey()
	if e != nil {
		return c, e
	}
	box, e := vaultwire.NewKey()
	if e != nil {
		return c, e
	}
	secret := make([]byte, 32)
	if _, e = rand.Read(secret); e != nil {
		return c, e
	}
	c = Config{Version: 1, Server: server, PrivateKey: key.Bytes(), BoxPrivate: box.Bytes(), PairingSecret: secret}
	c.Device = vaultwire.DeviceDescriptor{Role: "client", ID: vaultwire.ID(key.PublicKey().Bytes()), Name: name, PublicKey: key.PublicKey().Bytes(), BoxPublic: box.PublicKey().Bytes()}
	return c, nil
}
func Load(path string) (Config, error) {
	var c Config
	b, e := cloudstore.ReadSecret(path, 32768)
	if e != nil {
		return c, errors.New("device is not configured; run vault pair first")
	}
	defer clear(b)
	if json.Unmarshal(b, &c) != nil || c.Version != 1 {
		return c, errors.New("invalid device configuration")
	}
	pub, e := vaultwire.Public(c.PrivateKey)
	box, e2 := vaultwire.Public(c.BoxPrivate)
	if e != nil || e2 != nil || !bytes.Equal(pub, c.Device.PublicKey) || !bytes.Equal(box, c.Device.BoxPublic) || vaultwire.ID(pub) != c.Device.ID || ValidateServer(c.Server) != nil {
		return Config{}, errors.New("invalid device keys or server")
	}
	if c.OwnerID != "" && (!vaultwire.ValidPublic(c.OwnerPublic) || !vaultwire.ValidPublic(c.OwnerBoxPublic)) {
		return Config{}, errors.New("invalid pinned owner keys")
	}
	return c, nil
}
func Save(path string, c Config) error {
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	defer clear(b)
	return SavePrivate(path, b)
}
func SavePrivate(path string, b []byte) error {
	dir := filepath.Dir(path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("configuration directory must be private (0700)")
	}
	if st, e = os.Lstat(path); e == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
		return errors.New("refusing to replace an unsafe configuration file")
	}
	f, e := os.CreateTemp(dir, ".vault-write-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}

type Client struct {
	Config Config
	HTTP   *http.Client
}

func New(c Config) *Client {
	return &Client{Config: c, HTTP: &http.Client{Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }
func (c *Client) Call(ctx context.Context, path string, input, output any) error {
	if !strings.HasPrefix(path, "/api/v1/device/") {
		return errors.New("invalid device API path")
	}
	b, e := json.Marshal(input)
	if e != nil {
		return e
	}
	defer clear(b)
	proof, e := vaultwire.Sign(c.Config.PrivateKey, "http", vaultwire.HTTPProof{DeviceID: c.Config.Device.ID, Method: "POST", Path: path, BodyHash: vaultwire.Digest(b), Nonce: RandomID(), At: time.Now().UTC()})
	if e != nil {
		return e
	}
	pb, _ := json.Marshal(proof)
	r, e := http.NewRequestWithContext(ctx, "POST", c.Config.Server+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Vault-Proof", base64.RawURLEncoding.EncodeToString(pb))
	res, e := c.HTTP.Do(r)
	if e != nil {
		return errors.New("Vault connection failed")
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 8*1024*1024+1))
	if e != nil || len(raw) > 8*1024*1024 {
		return errors.New("invalid Vault response")
	}
	defer clear(raw)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var detail struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &detail)
		if detail.Error == "" || len(detail.Error) > 200 {
			detail.Error = "Vault request failed"
		}
		return &APIError{res.StatusCode, detail.Error}
	}
	if output != nil && json.Unmarshal(raw, output) != nil {
		return errors.New("invalid Vault response")
	}
	return nil
}
func (c *Client) Enroll(ctx context.Context) (string, error) {
	if e := c.Call(ctx, "/api/v1/device/enroll", vaultwire.Enrollment{Device: c.Config.Device, PairingHash: vaultwire.Digest(c.Config.PairingSecret)}, nil); e != nil {
		return "", e
	}
	code := struct {
		Version     int                        `json:"version"`
		Device      vaultwire.DeviceDescriptor `json:"device"`
		Secret      []byte                     `json:"secret"`
		Fingerprint string                     `json:"fingerprint"`
	}{1, c.Config.Device, c.Config.PairingSecret, vaultwire.Digest(c.Config.Device.PublicKey)}
	b, _ := json.Marshal(code)
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (c *Client) FinishPair(ctx context.Context) error {
	var status struct {
		Paired bool                `json:"paired"`
		Box    *vaultwire.Envelope `json:"box"`
	}
	if e := c.Call(ctx, "/api/v1/device/pairing", struct{}{}, &status); e != nil {
		return e
	}
	if !status.Paired || status.Box == nil {
		return ErrPending
	}
	b, e := vaultwire.Open(c.Config.BoxPrivate, "pair:"+c.Config.Device.ID, *status.Box)
	if e != nil {
		return errors.New("pairing response decryption failed")
	}
	defer clear(b)
	var pairing vaultwire.Pairing
	if json.Unmarshal(b, &pairing) != nil || pairing.DeviceID != c.Config.Device.ID || !vaultwire.ValidPublic(pairing.OwnerPublic) || !vaultwire.ValidPublic(pairing.OwnerBoxPublic) {
		return errors.New("invalid pairing response")
	}
	payload, _ := json.Marshal(struct {
		DeviceID       string `json:"deviceId"`
		OwnerID        string `json:"ownerId"`
		OwnerPublic    []byte `json:"ownerPublic"`
		OwnerBoxPublic []byte `json:"ownerBoxPublic"`
	}{pairing.DeviceID, pairing.OwnerID, pairing.OwnerPublic, pairing.OwnerBoxPublic})
	if !hmac.Equal(pairing.MAC, vaultwire.PairMAC(c.Config.PairingSecret, payload)) {
		return errors.New("pairing code was not verified by the owner")
	}
	c.Config.OwnerID = pairing.OwnerID
	c.Config.OwnerPublic = pairing.OwnerPublic
	c.Config.OwnerBoxPublic = pairing.OwnerBoxPublic
	clear(c.Config.PairingSecret)
	c.Config.PairingSecret = nil
	return nil
}

var ErrPending = errors.New("waiting for approval")

type Pending struct {
	Request  vaultwire.Request `json:"request"`
	Signed   vaultwire.Signed  `json:"signed"`
	Receiver *vaultwire.Signed `json:"receiver,omitempty"`
	Private  []byte            `json:"private,omitempty"`
}

func (c *Client) Submit(ctx context.Context, q vaultwire.Request) (Pending, error) {
	var p Pending
	if c.Config.OwnerID == "" {
		return p, errors.New("pair this device before requesting access")
	}
	q.ID = RandomID()
	q.DeviceID = c.Config.Device.ID
	if q.AgentID == "" {
		q.AgentID = q.DeviceID
	}
	q.CreatedAt = time.Now().UTC()
	q.ExpiresAt = q.CreatedAt.Add(10 * time.Minute)
	if q.Session == "" {
		q.Session = "cli-" + q.ID[:16]
	}
	if q.Duration == 0 {
		q.Duration = 900
	}
	p.Request = q
	var e error
	p.Signed, e = vaultwire.Sign(c.Config.PrivateKey, "request", q)
	if e != nil {
		return p, e
	}
	if !q.Managed && q.AgentID == q.DeviceID && q.Kind != "create" && q.Kind != "import" && q.Kind != "lookup" && q.Kind != "keychain-import" {
		key, e := vaultwire.NewKey()
		if e != nil {
			return p, e
		}
		p.Private = key.Bytes()
		receiver, e := vaultwire.Sign(c.Config.PrivateKey, "receiver", vaultwire.Receiver{RequestID: q.ID, RequestHash: vaultwire.Digest(p.Signed.Payload), PublicKey: key.PublicKey().Bytes(), ExpiresAt: q.ExpiresAt.Add(time.Duration(q.Duration) * time.Second)})
		if e != nil {
			return p, e
		}
		p.Receiver = &receiver
	}
	in := struct {
		Signed   vaultwire.Signed  `json:"signed"`
		Receiver *vaultwire.Signed `json:"receiver,omitempty"`
	}{p.Signed, p.Receiver}
	e = c.Call(ctx, "/api/v1/device/requests", in, nil)
	return p, e
}
func (c *Client) Status(ctx context.Context, id string) (vaultwire.RequestState, error) {
	var state vaultwire.RequestState
	e := c.Call(ctx, "/api/v1/device/requests/"+id, struct{}{}, &state)
	return state, e
}
func (c *Client) Revoke(ctx context.Context, id string) error {
	return c.Call(ctx, "/api/v1/device/requests/"+id+"/revoke", struct{}{}, nil)
}
func (c *Client) Wait(ctx context.Context, p Pending, progress io.Writer) (vaultwire.RequestState, error) {
	if progress != nil {
		fmt.Fprintf(progress, "Waiting for approval in %s/app · session %s\n", c.Config.Server, p.Request.Session)
	}
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		q, e := c.Status(ctx, p.Request.ID)
		if e != nil {
			return q, e
		}
		switch q.Status {
		case "approved", "completed":
			return q, nil
		case "declined", "revoked":
			return q, fmt.Errorf("request %s", q.Status)
		case "pending":
		default:
			return q, errors.New("invalid request status")
		}
		select {
		case <-ctx.Done():
			return q, ctx.Err()
		case <-timer.C:
		}
	}
}
func (c *Client) Approval(p Pending, state vaultwire.RequestState) (vaultwire.Approval, error) {
	var a vaultwire.Approval
	if state.Status != "approved" || state.Box == nil || p.Receiver == nil || p.Request.AgentID != c.Config.Device.ID {
		return a, errors.New("request has no local approval")
	}
	b, e := vaultwire.Open(p.Private, "approval:"+p.Request.ID, *state.Box)
	if e != nil {
		return a, errors.New("approval could not be decrypted")
	}
	defer clear(b)
	var signed vaultwire.Signed
	if json.Unmarshal(b, &signed) != nil || vaultwire.Verify(c.Config.OwnerPublic, "approval", signed, &a) != nil {
		return a, errors.New("owner approval rejected")
	}
	if a.RequestID != p.Request.ID || a.RequestHash != vaultwire.Digest(p.Signed.Payload) || a.ReceiverHash != vaultwire.Digest(p.Receiver.Payload) || a.IdentityType != p.Request.IdentityType || a.IdentityID == "" || !time.Now().Before(a.ExpiresAt) || time.Until(a.ExpiresAt) > time.Duration(p.Request.Duration)*time.Second || len(a.Secret) == 0 {
		return vaultwire.Approval{}, errors.New("approval does not match the requested identity, scope or deadline")
	}
	return a, nil
}
func (c *Client) Response(p Pending, state vaultwire.RequestState) ([]byte, error) {
	var response vaultwire.Response
	if state.Response == nil || vaultwire.Verify(c.Config.OwnerPublic, "response", *state.Response, &response) != nil || response.RequestID != p.Request.ID || response.RequestHash != vaultwire.Digest(p.Signed.Payload) || !time.Now().Before(response.ExpiresAt) {
		return nil, errors.New("owner response rejected")
	}
	if response.Error != "" {
		return nil, errors.New("request could not be completed")
	}
	return response.Result, nil
}

// Watch cancels the local operation on expiry, revocation, device revocation,
// or loss of relay contact. It cannot retract a credential already exported.
func (c *Client) Watch(ctx context.Context, id string, cancel context.CancelFunc) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			q, e := c.Status(ctx, id)
			if e != nil || q.Status != "approved" || !time.Now().Before(q.ExpiresAt) {
				cancel()
				return
			}
		}
	}
}
func (c *Client) CloseRequest(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Revoke(ctx, id); err != nil {
		fmt.Fprintln(os.Stderr, "Vault could not confirm revocation; the approval deadline still applies:", err)
	}
}
