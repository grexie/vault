package deviceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/vaultwire"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSecurityReviewEncryptedRPCBindsRequesterNonceAndRevocation(t *testing.T) {
	ctx := context.Background()
	var revoked atomic.Bool
	owner, _ := vaultwire.NewKey()
	var state vaultwire.RequestState
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() {
			http.Error(w, "revoked", 403)
			return
		}
		json.NewEncoder(w).Encode(state)
	}))
	defer cloud.Close()
	requesterCfg, err := device.NewConfig(cloud.URL, "Requester")
	if err != nil {
		t.Fatal(err)
	}
	agentCfg, err := device.NewConfig(cloud.URL, "Agent")
	if err != nil {
		t.Fatal(err)
	}
	requesterCfg.OwnerID = "fixture-owner"
	requesterCfg.OwnerPublic = owner.PublicKey().Bytes()
	agentCfg.OwnerID = requesterCfg.OwnerID
	agentCfg.OwnerPublic = requesterCfg.OwnerPublic
	requesterCfg.Device.Role = "client"
	agentCfg.Device.Role = "agent"
	requester := device.New(requesterCfg)
	a := New(device.New(agentCfg))
	defer a.Close()
	q := vaultwire.Request{ID: device.RandomID(), DeviceID: requesterCfg.Device.ID, AgentID: agentCfg.Device.ID, Kind: "ssh", IdentityType: "ssh", Managed: true, Duration: 60, ExpiresAt: time.Now().Add(time.Minute)}
	signed, err := vaultwire.Sign(requesterCfg.PrivateKey, "request", q)
	if err != nil {
		t.Fatal(err)
	}
	receiverKey, _ := vaultwire.NewKey()
	receiver, err := vaultwire.Sign(agentCfg.PrivateKey, "receiver", vaultwire.Receiver{RequestID: q.ID, RequestHash: vaultwire.Digest(signed.Payload), PublicKey: receiverKey.PublicKey().Bytes(), ExpiresAt: q.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := vaultwire.Sign(owner.Bytes(), "authorization", vaultwire.Authorization{RequestID: q.ID, RequestHash: vaultwire.Digest(signed.Payload), ReceiverHash: vaultwire.Digest(receiver.Payload), AgentPublic: agentCfg.Device.PublicKey, ExpiresAt: q.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	_, sshKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sshKey)
	ring := agent.NewKeyring()
	if err = ring.Add(agent.AddedKey{PrivateKey: sshKey}); err != nil {
		t.Fatal(err)
	}
	p := device.Pending{Request: q, Signed: signed, Receiver: &receiver}
	a.leases[q.ID] = &lease{pending: device.Pending{Request: q, Signed: signed, Receiver: &receiver, Private: receiverKey.Bytes()}, approval: &vaultwire.Approval{RequesterPublic: requesterCfg.Device.PublicKey, ExpiresAt: q.ExpiresAt}, ring: ring, used: map[string]time.Time{}}
	state = vaultwire.RequestState{ID: q.ID, Status: "approved", Receiver: &receiver, Authorization: &authorization, ExpiresAt: q.ExpiresAt}
	endpoint := httptest.NewServer(a.Handler())
	defer endpoint.Close()
	list := []byte{0, 0, 0, 1, 11}
	response, err := requester.RPC(ctx, endpoint.URL, p, state, "ssh", list)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ssh.NewSignerFromKey(sshKey)
	if len(response) < 5 || response[4] != 12 || !bytes.Contains(response, pub.PublicKey().Marshal()) {
		t.Fatal("valid request did not reach the approved keyring")
	}
	if _, err = requester.RPC(ctx, endpoint.URL, p, state, "ethereum", []byte("other operation")); err == nil {
		t.Fatal("SSH approval accepted transaction signing")
	}
	// Construct a single signed wire request so an identical replay can be tested.
	replyKey, _ := vaultwire.NewKey()
	rpc := vaultwire.RPC{RequestID: q.ID, Nonce: device.RandomID(), Method: "ping", ReplyPublic: replyKey.PublicKey().Bytes(), ExpiresAt: time.Now().Add(30 * time.Second)}
	body := func(private []byte, value vaultwire.RPC) []byte {
		t.Helper()
		message, e := vaultwire.Sign(private, "rpc", value)
		if e != nil {
			t.Fatal(e)
		}
		plain, e := json.Marshal(message)
		if e != nil {
			t.Fatal(e)
		}
		box, e := vaultwire.Seal(receiverKey.PublicKey().Bytes(), "rpc:"+q.ID, plain)
		if e != nil {
			t.Fatal(e)
		}
		b, e := json.Marshal(map[string]any{"requestId": q.ID, "box": box})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	send := func(b []byte, origin string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest("POST", endpoint.URL+"/v1/rpc", bytes.NewReader(b))
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		return w
	}
	b := body(requesterCfg.PrivateKey, rpc)
	if w := send(b, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := send(b, ""); w.Code != 409 {
		t.Fatal("RPC replay accepted", w.Code)
	}
	stranger, _ := vaultwire.NewKey()
	rpc.Nonce = device.RandomID()
	if w := send(body(stranger.Bytes(), rpc), ""); w.Code != 403 {
		t.Fatal("unapproved requester accepted", w.Code)
	}
	rpc.Nonce = device.RandomID()
	rpc.ExpiresAt = time.Now().Add(-time.Second)
	if w := send(body(requesterCfg.PrivateKey, rpc), ""); w.Code != 403 {
		t.Fatal("expired proof accepted", w.Code)
	}
	rpc.Nonce = device.RandomID()
	rpc.ExpiresAt = time.Now().Add(30 * time.Second)
	if w := send(body(requesterCfg.PrivateKey, rpc), "https://attacker.example"); w.Code != 404 {
		t.Fatal("browser-origin RPC accepted", w.Code)
	}
	revoked.Store(true)
	if _, err = requester.RPC(ctx, endpoint.URL, p, state, "ssh", list); err == nil {
		t.Fatal("RPC remained usable after cloud revocation")
	}
	a.mu.Lock()
	remaining := len(a.leases)
	a.mu.Unlock()
	if remaining != 0 {
		t.Fatal("revocation retained keyring")
	}
}

func TestSecurityReviewTransactionApprovalIsOneShotAndExact(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.D.SetInt64(0)
	raw := []byte(`{"from":"` + crypto.PubkeyToAddress(key.PublicKey).Hex() + `","to":"0x2222222222222222222222222222222222222222","chainId":"0x1","nonce":"0x0","gas":"0x5208","gasPrice":"0x1","value":"0x0"}`)
	secret := []byte(hex.EncodeToString(crypto.FromECDSA(key)))
	defer clear(secret)
	l := &lease{pending: device.Pending{Request: vaultwire.Request{Kind: "ethereum", Payload: raw}}, approval: &vaultwire.Approval{Secret: secret}}
	changed := []byte(strings.Replace(string(raw), `"value":"0x0"`, `"value":"0x1"`, 1))
	if _, err = l.execute(vaultwire.RPC{Method: "ethereum", Data: changed}); err == nil {
		t.Fatal("different transaction signed")
	}
	signed, err := l.execute(vaultwire.RPC{Method: "ethereum", Data: raw})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = identity.VerifyEthereum(raw, signed); err != nil {
		t.Fatal(err)
	}
	if _, err = l.execute(vaultwire.RPC{Method: "ethereum", Data: raw}); err == nil {
		t.Fatal("one-shot approval reused")
	}
}

func TestSecurityReviewRSARejectsLegacySHA1AndVerifiesSHA2(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ring := agent.NewKeyring()
	if err = ring.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		t.Fatal(err)
	}
	defer ring.RemoveAll()
	signer, _ := ssh.NewSignerFromKey(key)
	data := []byte("synthetic SSH authentication request")
	l := &lease{pending: device.Pending{Request: vaultwire.Request{Kind: "ssh"}}, ring: ring}
	packet := func(flags uint32) []byte {
		p := ssh.Marshal(struct {
			Type      byte
			Key, Data []byte
			Flags     uint32
		}{13, signer.PublicKey().Marshal(), data, flags})
		out := make([]byte, 4+len(p))
		binary.BigEndian.PutUint32(out, uint32(len(p)))
		copy(out[4:], p)
		return out
	}
	for _, flags := range []uint32{0, 1, 6, 8} {
		if _, err = l.execute(vaultwire.RPC{Method: "ssh", Data: packet(flags)}); err == nil {
			t.Fatalf("unsafe RSA flags %d accepted", flags)
		}
	}
	for _, flags := range []uint32{uint32(agent.SignatureFlagRsaSha256), uint32(agent.SignatureFlagRsaSha512)} {
		out, err := l.execute(vaultwire.RPC{Method: "ssh", Data: packet(flags)})
		if err != nil {
			t.Fatal(err)
		}
		var reply struct {
			Type byte
			Blob []byte
		}
		if len(out) < 5 || ssh.Unmarshal(out[4:], &reply) != nil || reply.Type != 14 {
			t.Fatal("invalid sign reply")
		}
		var signature ssh.Signature
		if ssh.Unmarshal(reply.Blob, &signature) != nil {
			t.Fatal("invalid signature")
		}
		if signature.Format == ssh.KeyAlgoRSA {
			t.Fatal("legacy SHA-1 signature returned")
		}
		if err = signer.PublicKey().Verify(data, &signature); err != nil {
			t.Fatal(err)
		}
	}
}
