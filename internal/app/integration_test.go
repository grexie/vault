package app

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/fxamacker/cbor/v2"
	"github.com/grexie/remote-ssh-agent/internal/signer"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 5 && os.Args[1] == "_signer" {
		n, _ := strconv.ParseInt(os.Args[4], 10, 64)
		if signer.Serve(os.Args[2], os.Args[3], time.Unix(n, 0), os.Stdin, os.Stdout) != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type harness struct {
	t                  *testing.T
	s                  *Server
	http               *http.Client
	origin             string
	authKey            *ecdsa.PrivateKey
	credentialID       []byte
	count              uint32
	key                ed25519.PrivateKey
	fingerprint, token string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	origin := "http://localhost:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	s, e := New(Config{Origin: origin, DataDir: t.TempDir()})
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go s.RunJanitor(ctx)
	server := &http.Server{Handler: s.Handler()}
	go server.Serve(ln)
	t.Cleanup(func() { cancel(); server.Close(); s.Close() })
	jar, _ := cookiejar.New(nil)
	authKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	sshKey, _ := ssh.NewSignerFromKey(key)
	h := &harness{t: t, s: s, http: &http.Client{Jar: jar, Timeout: 10 * time.Second}, origin: origin, authKey: authKey, credentialID: id, key: key, fingerprint: ssh.FingerprintSHA256(sshKey.PublicKey())}
	h.register()
	h.saveKey()
	var client struct {
		Token string `json:"token"`
	}
	h.call("POST", "/api/clients", "", map[string]string{"name": "Test Codex"}, &client, 201)
	h.token = client.Token
	return h
}
func (h *harness) call(method, path, token string, in, out any, want int) {
	h.t.Helper()
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, h.origin+path, body)
	r.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(path, "/api/") {
		r.Header.Set("Origin", h.origin)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, e := h.http.Do(r)
	if e != nil {
		h.t.Fatal(e)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		h.t.Fatalf("%s %s: got %d, want %d: %s", method, path, res.StatusCode, want, b)
	}
	if out != nil {
		if e = json.Unmarshal(b, out); e != nil {
			h.t.Fatal(e)
		}
	}
}

type start struct {
	Ceremony string `json:"ceremony"`
	Options  struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	} `json:"options"`
	PublicKey []byte `json:"publicKey"`
}

func url64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func (h *harness) register() {
	var v start
	h.call("POST", "/api/setup/begin", "", map[string]string{"token": h.s.bootstrap}, &v, 200)
	client, _ := json.Marshal(map[string]any{"type": "webauthn.create", "challenge": v.Options.PublicKey.Challenge, "origin": h.origin, "crossOrigin": false})
	cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: h.authKey.X.FillBytes(make([]byte, 32)), -3: h.authKey.Y.FillBytes(make([]byte, 32))})
	rp := sha256.Sum256([]byte("localhost"))
	auth := append([]byte{}, rp[:]...)
	auth = append(auth, 0x45, 0, 0, 0, 0)
	auth = append(auth, make([]byte, 16)...)
	auth = append(auth, 0, byte(len(h.credentialID)))
	auth = append(auth, h.credentialID...)
	auth = append(auth, cose...)
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "authData": auth, "attStmt": map[string]any{}})
	c := map[string]any{"id": url64(h.credentialID), "rawId": url64(h.credentialID), "type": "public-key", "response": map[string]any{"clientDataJSON": url64(client), "attestationObject": url64(att)}, "clientExtensionResults": map[string]any{"prf": map[string]bool{"enabled": true}, "largeBlob": map[string]bool{"supported": true}}}
	h.call("POST", "/api/setup/finish", "", map[string]any{"ceremony": v.Ceremony, "credential": c}, nil, 200)
}
func (h *harness) assertion(challenge, origin string, uv bool, write bool) map[string]any {
	client, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte("localhost"))
	auth := append([]byte{}, rp[:]...)
	flags := byte(1)
	if uv {
		flags |= 4
	}
	auth = append(auth, flags)
	h.count++
	auth = binary.BigEndian.AppendUint32(auth, h.count)
	hash := sha256.Sum256(client)
	signed := append(append([]byte{}, auth...), hash[:]...)
	digest := sha256.Sum256(signed)
	signature, _ := ecdsa.SignASN1(rand.Reader, h.authKey, digest[:])
	ext := map[string]any{}
	if write {
		ext["largeBlob"] = map[string]bool{"written": true}
	}
	return map[string]any{"id": url64(h.credentialID), "rawId": url64(h.credentialID), "type": "public-key", "response": map[string]any{"clientDataJSON": url64(client), "authenticatorData": url64(auth), "signature": url64(signature)}, "clientExtensionResults": ext}
}
func (h *harness) saveKey() {
	var v start
	h.call("POST", "/api/key/write/begin", "", map[string]string{"name": "Test key", "fingerprint": h.fingerprint}, &v, 200)
	h.call("POST", "/api/key/write/finish", "", map[string]any{"ceremony": v.Ceremony, "credential": h.assertion(v.Options.PublicKey.Challenge, h.origin, true, true)}, nil, 200)
}

type lease struct {
	Request    Request `json:"request"`
	Capability string  `json:"capability"`
}

func (h *harness) request(session string, duration int) lease {
	var l lease
	h.call("POST", "/v1/requests", h.token, map[string]any{"session": session, "reason": "Deploy the tested API fix", "socket": "/tmp/test-" + session + ".sock", "durationSeconds": duration}, &l, 201)
	return l
}
func (h *harness) envelope(pub []byte, id string) signer.Envelope {
	h.t.Helper()
	pair, _ := ecdh.P256().GenerateKey(rand.Reader)
	recipient, e := ecdh.P256().NewPublicKey(pub)
	if e != nil {
		h.t.Fatal(e)
	}
	secret, _ := pair.ECDH(recipient)
	salt := make([]byte, 32)
	_, _ = rand.Read(salt)
	aad := signer.Context(id, h.fingerprint)
	aesKey := make([]byte, 32)
	_, _ = io.ReadFull(hkdf.New(sha256.New, secret, salt, aad), aesKey)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	pemKey, _ := ssh.MarshalPrivateKey(h.key, "generated integration key")
	plain, _ := json.Marshal(map[string]string{"key": string(pem.EncodeToMemory(pemKey)), "passphrase": ""})
	return signer.Envelope{PublicKey: pair.PublicKey().Bytes(), Salt: salt, IV: iv, Ciphertext: gcm.Seal(nil, iv, plain, aad)}
}
func (h *harness) approve(l lease) {
	var v start
	path := "/api/requests/" + l.Request.ID + "/approve"
	h.call("POST", path+"/begin", "", map[string]any{}, &v, 200)
	h.call("POST", path+"/finish", "", map[string]any{"ceremony": v.Ceremony, "credential": h.assertion(v.Options.PublicKey.Challenge, h.origin, true, false), "envelope": h.envelope(v.PublicKey, l.Request.ID)}, nil, 200)
}
func (h *harness) sign(l lease, want int) {
	h.t.Helper()
	key, _ := ssh.NewSignerFromKey(h.key)
	message := []byte("synthetic SSH authentication exchange")
	var reply signer.Reply
	h.call("POST", "/v1/requests/"+l.Request.ID+"/agent", l.Capability, signer.Message{Action: "sign", Key: key.PublicKey().Marshal(), Data: message}, &reply, want)
	if want == 200 {
		if e := key.PublicKey().Verify(message, reply.Signature); e != nil {
			h.t.Fatal(e)
		}
	}
}

func TestApprovalIsolationRevocationAndExpiry(t *testing.T) {
	h := newHarness(t)
	a := h.request("codex-a", 30)
	b := h.request("codex-b", 30)
	h.sign(a, 403)
	h.approve(a)
	h.approve(b)
	h.sign(a, 200)
	h.sign(b, 200)
	h.call("POST", "/v1/requests/"+a.Request.ID+"/agent", b.Capability, signer.Message{Action: "list"}, nil, 401)
	h.call("POST", "/api/requests/"+a.Request.ID+"/revoke", "", map[string]any{}, nil, 200)
	h.sign(a, 403)
	h.sign(b, 200)
	h.call("POST", "/v1/revoke", h.token, map[string]string{"session": "codex-b"}, nil, 200)
	h.sign(b, 403)
	c := h.request("short", 1)
	h.approve(c)
	h.sign(c, 200)
	time.Sleep(1100 * time.Millisecond)
	h.sign(c, 403)
	d := h.request("denied", 30)
	h.call("POST", "/api/requests/"+d.Request.ID+"/revoke", "", map[string]any{}, nil, 200)
	h.call("POST", "/api/requests/"+d.Request.ID+"/approve/begin", "", map[string]any{}, nil, 409)
}
func TestFreshVerificationAndBoundCeremonies(t *testing.T) {
	h := newHarness(t)
	a := h.request("one", 30)
	b := h.request("two", 30)
	for _, scenario := range []string{"no-UV", "wrong-origin", "wrong-challenge"} {
		t.Run(scenario, func(t *testing.T) {
			var v start
			path := "/api/requests/" + a.Request.ID + "/approve"
			h.call("POST", path+"/begin", "", map[string]any{}, &v, 200)
			origin, challenge, uv := h.origin, v.Options.PublicKey.Challenge, true
			if scenario == "no-UV" {
				uv = false
			}
			if scenario == "wrong-origin" {
				origin = "https://attacker.invalid"
			}
			if scenario == "wrong-challenge" {
				challenge = randomToken()
			}
			in := map[string]any{"ceremony": v.Ceremony, "credential": h.assertion(challenge, origin, uv, false), "envelope": h.envelope(v.PublicKey, a.Request.ID)}
			h.call("POST", path+"/finish", "", in, nil, 401)
			h.call("POST", path+"/finish", "", in, nil, 400)
			h.sign(a, 403)
		})
	}
	var v start
	h.call("POST", "/api/requests/"+a.Request.ID+"/approve/begin", "", map[string]any{}, &v, 200)
	h.call("POST", "/api/requests/"+b.Request.ID+"/approve/finish", "", map[string]any{"ceremony": v.Ceremony, "credential": h.assertion(v.Options.PublicKey.Challenge, h.origin, true, false), "envelope": h.envelope(v.PublicKey, a.Request.ID)}, nil, 400)
	h.sign(b, 403)
}
func TestRejectInvalidRequestsAndForeignOrigins(t *testing.T) {
	h := newHarness(t)
	for _, d := range []int{0, -1, 3601} {
		h.call("POST", "/v1/requests", h.token, map[string]any{"session": "bad", "reason": "valid justification", "socket": "/tmp/a.sock", "durationSeconds": d}, nil, 400)
	}
	h.call("POST", "/v1/requests", h.token, map[string]any{"session": "bad", "reason": " ", "socket": "/tmp/a.sock", "durationSeconds": 60}, nil, 400)
	r, _ := http.NewRequest("POST", h.origin+"/api/clients", strings.NewReader(`{"name":"evil"}`))
	r.Header.Set("Origin", "https://attacker.invalid")
	res, e := h.http.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("cross-origin mutation accepted")
	}
	r, _ = http.NewRequest("GET", h.origin+"/api/info", nil)
	r.Host = "attacker.invalid"
	res, e = h.http.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("foreign host accepted")
	}
	a := h.request("duplicate", 60)
	_ = a
	h.call("POST", "/v1/requests", h.token, map[string]any{"session": "duplicate", "reason": "valid justification", "socket": "/tmp/a.sock", "durationSeconds": 60}, nil, 409)
}
func TestRestartRevokesAndDBHasNoKey(t *testing.T) {
	h := newHarness(t)
	l := h.request("restart", 60)
	h.approve(l)
	dir := h.s.config.DataDir
	if e := h.s.Close(); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(dir + "/metadata.db")
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("private key written to BoltDB")
	}
	s, e := New(Config{Origin: h.origin, DataDir: dir})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.state.Requests[l.Request.ID].Status != "revoked" {
		t.Fatal("grant survived restart")
	}
	if len(s.live) != 0 {
		t.Fatal("capability survived restart")
	}
	if len(s.state.Clients) != 1 {
		t.Fatal("paired client lost")
	}
}
func TestPushSubscriptionValidation(t *testing.T) {
	for _, host := range []string{"https://127.0.0.1/push", "http://fcm.googleapis.com/x", "https://fcm.googleapis.com.evil.invalid/x", "https://fcm.googleapis.com:444/x"} {
		if validPush(pushSub(host)) {
			t.Fatalf("SSRF endpoint allowed: %s", host)
		}
	}
	h := newHarness(t)
	for i := 0; i < 2; i++ {
		h.call("POST", "/api/push", "", pushSub(fmt.Sprintf("https://web.push.apple.com/device-%d", i)), nil, 200)
	}
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if len(h.s.state.Push) != 2 {
		t.Fatal("second device replaced first subscription")
	}
}

func pushSub(endpoint string) webpush.Subscription {
	return webpush.Subscription{Endpoint: endpoint, Keys: webpush.Keys{Auth: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), P256dh: base64.RawURLEncoding.EncodeToString(make([]byte, 65))}}
}
