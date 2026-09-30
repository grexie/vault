package deviceagent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/hyperliquid"
	"github.com/grexie/vault/internal/vaultwire"
	"github.com/grexie/vault/internal/walletsign"
)

// Public disposable SDK fixture key. Never fund. All requests in this file use
// local fake services; no signed transaction or action is broadcast.
const walletReviewKey = "0123456789012345678901234567890123456789012345678901234567890123"

func walletReviewFixture(t *testing.T) (*ecdsa.PrivateKey, walletsign.Payload, []byte, string) {
	t.Helper()
	key, err := crypto.HexToECDSA(walletReviewKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { key.D.SetInt64(0) })
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()
	// ERC-20 transfer of seven synthetic units to 0x3333...; nonce/fees are
	// explicit so the reviewed transaction cannot be completed differently.
	calldata := "0xa9059cbb" + strings.Repeat("0", 24) + strings.Repeat("3", 40) + strings.Repeat("0", 63) + "7"
	transaction := json.RawMessage(fmt.Sprintf(`{"from":%q,"to":"0x2222222222222222222222222222222222222222","chainId":"0x1","nonce":"0x0","gas":"0xc350","gasPrice":"0x1","value":"0x0","data":%q}`, address, calldata))
	p := walletsign.Payload{Origin: "https://approved.example", IdentityID: "fixture-identity", Identity: "Fixture Ethereum", Address: address, ChainID: "0x1", Method: "eth_sendTransaction", Data: transaction, Submit: true, RPCURL: "https://approved-rpc.example"}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = walletsign.Decode(raw); err != nil {
		t.Fatal("invalid wallet fixture", err)
	}
	return key, p, raw, "0x" + hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))
}

func walletReviewLease(p walletsign.Payload, raw []byte, pub string) *lease {
	return &lease{pending: device.Pending{Request: vaultwire.Request{Kind: "wallet-sign", Identity: p.Identity, IdentityType: "ethereum", Network: p.ChainID, Payload: append([]byte{}, raw...), Managed: true, Duration: 60}}, approval: &vaultwire.Approval{IdentityID: p.IdentityID, IdentityType: "ethereum", PublicKey: pub, Secret: []byte(walletReviewKey)}}
}

func TestSecurityWalletApprovalRejectsEveryPayloadSubstitution(t *testing.T) {
	_, p, raw, pub := walletReviewFixture(t)
	mutations := map[string]func(*walletsign.Payload){
		"origin":            func(p *walletsign.Payload) { p.Origin = "https://different.example" },
		"identity-id":       func(p *walletsign.Payload) { p.IdentityID = "another-identity" },
		"identity-name":     func(p *walletsign.Payload) { p.Identity = "Another Ethereum" },
		"address":           func(p *walletsign.Payload) { p.Address = "0x4444444444444444444444444444444444444444" },
		"chain":             func(p *walletsign.Payload) { p.ChainID = "0x89" },
		"rpc-endpoint":      func(p *walletsign.Payload) { p.RPCURL = "https://different-rpc.example" },
		"submission-intent": func(p *walletsign.Payload) { p.Submit = false; p.Method = "eth_signTransaction" },
		"contract-recipient": func(p *walletsign.Payload) {
			p.Data = bytes.Replace(p.Data, []byte(strings.Repeat("2", 40)), []byte(strings.Repeat("5", 40)), 1)
		},
		"token-recipient": func(p *walletsign.Payload) {
			p.Data = bytes.Replace(p.Data, []byte(strings.Repeat("3", 40)), []byte(strings.Repeat("6", 40)), 1)
		},
		"calldata": func(p *walletsign.Payload) {
			p.Data = bytes.Replace(p.Data, []byte("0xa9059cbb"), []byte("0x095ea7b3"), 1)
		},
		"value": func(p *walletsign.Payload) {
			p.Data = bytes.Replace(p.Data, []byte(`"value":"0x0"`), []byte(`"value":"0x1"`), 1)
		},
		"nonce": func(p *walletsign.Payload) {
			p.Data = bytes.Replace(p.Data, []byte(`"nonce":"0x0"`), []byte(`"nonce":"0x1"`), 1)
		},
		"gas-price": func(p *walletsign.Payload) {
			p.Data = bytes.Replace(p.Data, []byte(`"gasPrice":"0x1"`), []byte(`"gasPrice":"0xffff"`), 1)
		},
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			l := walletReviewLease(p, raw, pub)
			defer clear(l.approval.Secret)
			altered := p
			altered.Data = append(json.RawMessage{}, p.Data...)
			change(&altered)
			data, _ := json.Marshal(altered)
			if bytes.Equal(data, raw) {
				t.Fatal("mutation did not alter the fixture")
			}
			if signature, err := l.execute(vaultwire.RPC{Method: "wallet-sign", Data: data}); err == nil || len(signature) != 0 {
				t.Fatal("substituted wallet payload signed")
			}
			if l.oneShotUsed || string(l.approval.Secret) != walletReviewKey {
				t.Fatal("rejected substitution consumed or altered the original approval")
			}
			signature, err := l.execute(vaultwire.RPC{Method: "wallet-sign", Data: raw})
			if err != nil || walletsign.Verify(raw, signature, pub) != nil {
				t.Fatal("original approval no longer works", err)
			}
			if !l.oneShotUsed || !bytes.Equal(l.approval.Secret, make([]byte, len(l.approval.Secret))) {
				t.Fatal("successful one-shot signing retained private key data")
			}
			if _, err = l.execute(vaultwire.RPC{Method: "wallet-sign", Data: raw}); err == nil {
				t.Fatal("one-shot wallet approval reused")
			}
		})
	}
	for _, method := range []string{"ethereum", "hyperliquid", "bitcoin", "ssh", "age"} {
		t.Run("cross-method/"+method, func(t *testing.T) {
			l := walletReviewLease(p, raw, pub)
			defer clear(l.approval.Secret)
			if _, err := l.execute(vaultwire.RPC{Method: method, Data: raw}); err == nil {
				t.Fatal("wallet approval accepted a different operation")
			}
		})
	}
}

func TestSecurityWalletChecksReleasedIdentityAndNestedAmbiguity(t *testing.T) {
	_, p, raw, pub := walletReviewFixture(t)
	for name, change := range map[string]func(*lease){
		"approved-identity-id":  func(l *lease) { l.approval.IdentityID = "different" },
		"request-identity-name": func(l *lease) { l.pending.Request.Identity = "different" },
		"request-chain":         func(l *lease) { l.pending.Request.Network = "0x89" },
		"unmanaged":             func(l *lease) { l.pending.Request.Managed = false },
		"long-lease":            func(l *lease) { l.pending.Request.Duration = 3600 },
		"wrong-public-key": func(l *lease) {
			other, _ := crypto.GenerateKey()
			defer other.D.SetInt64(0)
			l.approval.PublicKey = hex.EncodeToString(crypto.FromECDSAPub(&other.PublicKey))
		},
	} {
		t.Run(name, func(t *testing.T) {
			l := walletReviewLease(p, raw, pub)
			defer clear(l.approval.Secret)
			change(l)
			if _, err := l.execute(vaultwire.RPC{Method: "wallet-sign", Data: raw}); err == nil {
				t.Fatal("inconsistent approval signed")
			}
		})
	}
	for name, data := range map[string][]byte{
		"wallet-case-alias":      []byte(strings.TrimSuffix(string(raw), "}") + `,"Origin":"https://other.example"}`),
		"wallet-duplicate":       []byte(strings.TrimSuffix(string(raw), "}") + `,"origin":"https://other.example"}`),
		"transaction-case-alias": bytes.Replace(raw, []byte(`"value":"0x0"`), []byte(`"value":"0x0","Value":"0x1"`), 1),
		"transaction-duplicate":  bytes.Replace(raw, []byte(`"value":"0x0"`), []byte(`"value":"0x0","value":"0x1"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			// Even if a malformed body reached an approval, the signer must
			// independently reject interpretation ambiguity inside its payload.
			l := walletReviewLease(p, data, pub)
			defer clear(l.approval.Secret)
			if _, err := l.execute(vaultwire.RPC{Method: "wallet-sign", Data: data}); err == nil {
				t.Fatal("ambiguous nested payload signed")
			}
		})
	}
}

func TestSecurityHyperliquidApprovalIsExactAndOneShot(t *testing.T) {
	key, err := crypto.HexToECDSA(walletReviewKey)
	if err != nil {
		t.Fatal(err)
	}
	defer key.D.SetInt64(0)
	pub := hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))
	// Already expired, testnet-only, no-op fixture. Never sent to an exchange.
	raw, err := hyperliquid.Prepare([]byte(`{"action":{"type":"noop"},"nonce":1700000000123,"expiresAfter":1700000000124}`), "testnet", crypto.PubkeyToAddress(key.PublicKey).Hex())
	if err != nil {
		t.Fatal(err)
	}
	newLease := func(data []byte) *lease {
		return &lease{pending: device.Pending{Request: vaultwire.Request{Kind: "hyperliquid", IdentityType: "ethereum", Network: "testnet", Managed: true, Duration: 60, Payload: append([]byte{}, data...)}}, approval: &vaultwire.Approval{IdentityID: "fixture", PublicKey: pub, Secret: []byte(walletReviewKey)}}
	}
	for name, data := range map[string][]byte{
		"network":         bytes.Replace(raw, []byte(`"network":"testnet"`), []byte(`"network":"mainnet"`), 1),
		"nonce":           bytes.Replace(raw, []byte(`1700000000123`), []byte(`1700000000122`), 1),
		"expiry":          bytes.Replace(raw, []byte(`1700000000124`), []byte(`1700000000125`), 1),
		"action":          bytes.Replace(raw, []byte(`"type":"noop"`), []byte(`"type":"scheduleCancel"`), 1),
		"vault-recipient": []byte(strings.TrimSuffix(string(raw), "}") + `,"vaultAddress":"0x1111111111111111111111111111111111111111"}`),
	} {
		t.Run(name, func(t *testing.T) {
			l := newLease(raw)
			defer clear(l.approval.Secret)
			if bytes.Equal(raw, data) {
				t.Fatal("mutation did not alter fixture")
			}
			if _, err := l.execute(vaultwire.RPC{Method: "hyperliquid", Data: data}); err == nil {
				t.Fatal("altered Hyperliquid action signed")
			}
			if l.oneShotUsed {
				t.Fatal("rejected action consumed approval")
			}
		})
	}
	for _, method := range []string{"wallet-sign", "ethereum", "bitcoin", "ssh", "age"} {
		l := newLease(raw)
		if _, err := l.execute(vaultwire.RPC{Method: method, Data: raw}); err == nil {
			t.Fatal("Hyperliquid approval accepted another method", method)
		}
		clear(l.approval.Secret)
	}
	malformed := bytes.Replace(raw, []byte(`"type":"noop"`), []byte(`"type":"noop","Type":"scheduleCancel"`), 1)
	l := newLease(malformed)
	if _, err := l.execute(vaultwire.RPC{Method: "hyperliquid", Data: malformed}); err == nil {
		t.Fatal("ambiguous Hyperliquid action signed")
	}
	clear(l.approval.Secret)
	l = newLease(raw)
	signed, err := l.execute(vaultwire.RPC{Method: "hyperliquid", Data: raw})
	if err != nil || hyperliquid.Verify(raw, signed, pub) != nil {
		t.Fatal("exact Hyperliquid action failed", err)
	}
	if !bytes.Equal(l.approval.Secret, make([]byte, len(l.approval.Secret))) {
		t.Fatal("Hyperliquid signing retained secret bytes")
	}
	if _, err = l.execute(vaultwire.RPC{Method: "hyperliquid", Data: raw}); err == nil {
		t.Fatal("Hyperliquid approval replayed")
	}
}

func TestSecurityWalletAgentPollRejectsSignedEnvelopeAlias(t *testing.T) {
	var requestState vaultwire.RequestState
	var receiverCalls atomic.Int64
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/device/inbox" {
			json.NewEncoder(w).Encode(map[string]any{"requests": []vaultwire.RequestState{requestState}})
			return
		}
		receiverCalls.Add(1)
		fmt.Fprint(w, `{}`)
	}))
	defer cloud.Close()
	config, err := device.NewConfig(cloud.URL, "Offline signing agent")
	if err != nil {
		t.Fatal(err)
	}
	requester, err := vaultwire.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	q := vaultwire.Request{ID: "ambiguous-offline-request", DeviceID: vaultwire.ID(requester.PublicKey().Bytes()), AgentID: config.Device.ID, Kind: "wallet-sign", IdentityType: "ethereum", Network: "0x1", Duration: 60, Managed: true, Payload: []byte(`{"display":"benign"}`), ExpiresAt: time.Now().Add(time.Minute)}
	raw, _ := json.Marshal(q)
	raw = []byte(strings.TrimSuffix(string(raw), "}") + `,"Payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"display":"malicious"}`)) + `"}`)
	signed, err := vaultwire.SignBytes(requester.Bytes(), "request", raw)
	if err != nil {
		t.Fatal(err)
	}
	requestState = vaultwire.RequestState{ID: q.ID, Status: "pending", Signed: signed, ExpiresAt: q.ExpiresAt}
	a := New(device.New(config))
	defer a.Close()
	a.poll(context.Background())
	if len(a.leases) != 0 || receiverCalls.Load() != 0 {
		t.Fatal("agent created a receiver for an ambiguous signed request")
	}
}

func TestSecurityWalletRPCBindsApprovedRequestAndAgent(t *testing.T) {
	_, payload, raw, pub := walletReviewFixture(t)
	var state vaultwire.RequestState
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(state) }))
	defer cloud.Close()
	owner, _ := vaultwire.NewKey()
	requesterConfig, _ := device.NewConfig(cloud.URL, "Offline wallet requester")
	agentConfig, _ := device.NewConfig(cloud.URL, "Offline wallet signer")
	requesterConfig.OwnerPublic, agentConfig.OwnerPublic = owner.PublicKey().Bytes(), owner.PublicKey().Bytes()
	requesterConfig.OwnerID, agentConfig.OwnerID = "fixture-owner", "fixture-owner"
	agentConfig.Device.Role = "agent"
	requester := device.New(requesterConfig)
	a := New(device.New(agentConfig))
	defer a.Close()
	l := walletReviewLease(payload, raw, pub)
	q := l.pending.Request
	q.ID, q.DeviceID, q.AgentID = device.RandomID(), requesterConfig.Device.ID, agentConfig.Device.ID
	q.ExpiresAt = time.Now().Add(45 * time.Second)
	signed, _ := vaultwire.Sign(requesterConfig.PrivateKey, "request", q)
	receiverKey, _ := vaultwire.NewKey()
	receiver, _ := vaultwire.Sign(agentConfig.PrivateKey, "receiver", vaultwire.Receiver{RequestID: q.ID, RequestHash: vaultwire.Digest(signed.Payload), PublicKey: receiverKey.PublicKey().Bytes(), ExpiresAt: q.ExpiresAt})
	authorization, _ := vaultwire.Sign(owner.Bytes(), "authorization", vaultwire.Authorization{RequestID: q.ID, RequestHash: vaultwire.Digest(signed.Payload), ReceiverHash: vaultwire.Digest(receiver.Payload), AgentPublic: agentConfig.Device.PublicKey, PublicKey: pub, ExpiresAt: q.ExpiresAt})
	pending := device.Pending{Request: q, Signed: signed, Receiver: &receiver}
	l.pending = pending
	l.pending.Private = receiverKey.Bytes()
	l.approval.RequesterPublic, l.approval.ExpiresAt = requesterConfig.Device.PublicKey, q.ExpiresAt
	l.used = map[string]time.Time{}
	a.leases[q.ID] = l
	state = vaultwire.RequestState{ID: q.ID, Status: "approved", Receiver: &receiver, Authorization: &authorization, ExpiresAt: q.ExpiresAt}
	ownerApproval, err := vaultwire.Sign(owner.Bytes(), "approval", vaultwire.Approval{RequestID: q.ID, RequestHash: vaultwire.Digest(signed.Payload), ReceiverHash: vaultwire.Digest(receiver.Payload), IdentityID: payload.IdentityID, IdentityType: "ethereum", PublicKey: pub, Secret: []byte(walletReviewKey), RequesterPublic: requesterConfig.Device.PublicKey, ExpiresAt: q.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	approvalBytes, _ := json.Marshal(ownerApproval)
	approvalBox, err := vaultwire.Seal(receiverKey.PublicKey().Bytes(), "approval:"+q.ID, approvalBytes)
	clear(approvalBytes)
	if err != nil {
		t.Fatal(err)
	}
	state.Box = &approvalBox
	agentClient := device.New(agentConfig)
	approved, err := agentClient.Approval(l.pending, state)
	if err != nil {
		t.Fatal("encrypted owner approval fixture rejected", err)
	}
	clear(approved.Secret)
	endpoint := httptest.NewServer(a.Handler())
	defer endpoint.Close()
	if _, _, err := requester.Authorization(pending, state); err != nil {
		t.Fatal("invalid owner approval fixture", err)
	}
	for name, change := range map[string]func(*vaultwire.Request){
		"identity": func(q *vaultwire.Request) { q.Identity = "Other identity" },
		"chain":    func(q *vaultwire.Request) { q.Network = "0x89" },
		"agent":    func(q *vaultwire.Request) { q.AgentID = "other-agent" },
		"method":   func(q *vaultwire.Request) { q.Kind = "ethereum" },
		"origin": func(q *vaultwire.Request) {
			p := payload
			p.Origin = "https://other.example"
			q.Payload, _ = json.Marshal(p)
		},
		"recipient": func(q *vaultwire.Request) {
			q.Payload = bytes.Replace(q.Payload, []byte(strings.Repeat("2", 40)), []byte(strings.Repeat("4", 40)), 1)
		},
		"calldata": func(q *vaultwire.Request) {
			q.Payload = bytes.Replace(q.Payload, []byte("0xa9059cbb"), []byte("0x095ea7b3"), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := pending
			change(&changed.Request)
			changed.Signed, _ = vaultwire.Sign(requesterConfig.PrivateKey, "request", changed.Request)
			if _, _, err := requester.Authorization(changed, state); err == nil {
				t.Fatal("owner authorization reused for a changed request")
			}
			changed.Private = receiverKey.Bytes()
			if leaked, err := agentClient.Approval(changed, state); err == nil {
				clear(leaked.Secret)
				t.Fatal("encrypted owner key approval reused for changed request context")
			}
		})
	}
	wrongAgent := pending
	wrongAgent.Request.AgentID = "other-agent"
	if _, _, err := requester.Authorization(wrongAgent, state); err == nil {
		t.Fatal("authorization accepted a different agent with unchanged signed bytes")
	}
	wrongReceiver := state
	otherKey, _ := vaultwire.NewKey()
	otherReceiver, _ := vaultwire.Sign(agentConfig.PrivateKey, "receiver", vaultwire.Receiver{RequestID: q.ID, RequestHash: vaultwire.Digest(signed.Payload), PublicKey: otherKey.PublicKey().Bytes(), ExpiresAt: q.ExpiresAt})
	wrongReceiver.Receiver = &otherReceiver
	if _, _, err := requester.Authorization(pending, wrongReceiver); err == nil {
		t.Fatal("authorization accepted a substituted receiver encryption key")
	}
	changedPayload := bytes.Replace(raw, []byte("https://approved.example"), []byte("https://other.example"), 1)
	if _, err := requester.RPC(context.Background(), endpoint.URL, pending, state, "wallet-sign", changedPayload); err == nil {
		t.Fatal("encrypted RPC accepted changed origin")
	}
	strangerConfig := requesterConfig
	stranger, _ := vaultwire.NewKey()
	strangerConfig.PrivateKey = stranger.Bytes()
	if _, err := device.New(strangerConfig).RPC(context.Background(), endpoint.URL, pending, state, "wallet-sign", raw); err == nil {
		t.Fatal("encrypted RPC accepted another requester key")
	}
	result, err := requester.RPC(context.Background(), endpoint.URL, pending, state, "wallet-sign", raw)
	if err != nil || walletsign.Verify(raw, result, pub) != nil {
		t.Fatal("approved encrypted wallet signing failed", err)
	}
	if _, err = requester.RPC(context.Background(), endpoint.URL, pending, state, "wallet-sign", raw); err == nil {
		t.Fatal("encrypted one-shot wallet request replayed")
	}
}
