// Package deviceagent holds approved keys on a user-controlled device. It never
// creates an SSH socket: authenticated encrypted RPC carries each operation.
package deviceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/hyperliquid"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/keyparse"
	"github.com/grexie/vault/internal/vaultwire"
	"github.com/grexie/vault/internal/walletsign"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type lease struct {
	pending     device.Pending
	approval    *vaultwire.Approval
	ring        agent.Agent
	age         age.Identity
	used        map[string]time.Time
	oneShotUsed bool
}
type Agent struct {
	client   *device.Client
	mu       sync.Mutex
	leases   map[string]*lease
	capacity chan struct{}
}

func New(c *device.Client) *Agent {
	return &Agent{client: c, leases: map[string]*lease{}, capacity: make(chan struct{}, 32)}
}
func (a *Agent) drop(id string) {
	if l := a.leases[id]; l != nil {
		clear(l.pending.Private)
		if l.approval != nil {
			clear(l.approval.Secret)
		}
		if l.ring != nil {
			l.ring.RemoveAll()
		}
		delete(a.leases, id)
	}
}
func (a *Agent) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id := range a.leases {
		a.drop(id)
	}
}
func (a *Agent) Run(ctx context.Context) {
	defer a.Close()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		a.poll(ctx)
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}
func (a *Agent) poll(ctx context.Context) {
	var inbox struct {
		Requests []vaultwire.RequestState `json:"requests"`
	}
	poll, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if a.client.Call(poll, "/api/v1/device/inbox", struct{}{}, &inbox) != nil {
		a.Close()
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	present := map[string]bool{}
	for _, state := range inbox.Requests {
		q, decodeErr := vaultwire.DecodeRequest(state.Signed.Payload)
		if decodeErr != nil || !q.Managed || q.AgentID != a.client.Config.Device.ID || state.ID != q.ID || !time.Now().Before(state.ExpiresAt) {
			continue
		}
		if q.Kind != "ssh" && q.Kind != "age" && q.Kind != "ethereum" && q.Kind != "bitcoin" && q.Kind != "hyperliquid" && q.Kind != "wallet-sign" {
			continue
		}
		present[q.ID] = true
		l := a.leases[q.ID]
		if l == nil {
			if state.Receiver != nil {
				continue
			} // Restart destroys the receiver secret; require fresh approval.
			if state.Status != "pending" || len(a.leases) >= 128 {
				continue
			}
			key, e := vaultwire.NewKey()
			if e != nil {
				continue
			}
			receiver, e := vaultwire.Sign(a.client.Config.PrivateKey, "receiver", vaultwire.Receiver{RequestID: q.ID, RequestHash: vaultwire.Digest(state.Signed.Payload), PublicKey: key.PublicKey().Bytes(), ExpiresAt: q.ExpiresAt.Add(time.Duration(q.Duration) * time.Second)})
			if e != nil {
				continue
			}
			if a.client.Call(poll, "/api/v1/device/requests/"+q.ID+"/receiver", map[string]any{"receiver": receiver}, nil) != nil {
				continue
			}
			l = &lease{pending: device.Pending{Request: q, Signed: state.Signed, Private: key.Bytes(), Receiver: &receiver}, used: map[string]time.Time{}}
			a.leases[q.ID] = l
		}
		if l.approval != nil {
			if !time.Now().Before(l.approval.ExpiresAt) {
				a.drop(q.ID)
			}
			continue
		}
		if state.Status != "approved" {
			continue
		}
		approval, e := a.client.Approval(l.pending, state)
		if e != nil || vaultwire.ID(approval.RequesterPublic) != q.DeviceID || vaultwire.Verify(approval.RequesterPublic, "request", state.Signed, &q) != nil {
			a.drop(q.ID)
			continue
		}
		l.approval = &approval
		if q.Kind == "ssh" || q.Kind == "age" {
			key, e := keyparse.ParseRaw(approval.Secret, nil)
			if e != nil {
				a.drop(q.ID)
				continue
			}
			signer, e := ssh.NewSignerFromKey(key)
			if e != nil || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) != strings.TrimSpace(approval.PublicKey) {
				a.drop(q.ID)
				continue
			}
			if q.Kind == "ssh" {
				l.ring = agent.NewKeyring()
				e = l.ring.Add(agent.AddedKey{PrivateKey: key, Comment: q.Identity, LifetimeSecs: uint32(time.Until(approval.ExpiresAt).Seconds())})
			} else {
				switch k := key.(type) {
				case ed25519.PrivateKey:
					l.age, e = agessh.NewEd25519Identity(k)
				case *ed25519.PrivateKey:
					l.age, e = agessh.NewEd25519Identity(*k)
				case *rsa.PrivateKey:
					l.age, e = agessh.NewRSAIdentity(k)
				default:
					e = errors.New("age requires RSA or Ed25519")
				}
			}
			if e != nil {
				a.drop(q.ID)
				continue
			}
			clear(l.approval.Secret)
		}
	}
	for id := range a.leases {
		if !present[id] {
			a.drop(id)
		}
	}
}

// Handler accepts only encrypted, freshly signed requests by the approved
// requester. A web origin, a relay cookie or possession of a lease ID is insufficient.
func (a *Agent) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "POST" || r.URL.Path != "/v1/rpc" || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			http.Error(w, "not found", 404)
			return
		}
		select {
		case a.capacity <- struct{}{}:
			defer func() { <-a.capacity }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		var in struct {
			RequestID string             `json:"requestId"`
			Box       vaultwire.Envelope `json:"box"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 7*1024*1024)).Decode(&in) != nil {
			http.Error(w, "invalid request", 400)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		l := a.leases[in.RequestID]
		if l == nil || l.approval == nil || !time.Now().Before(l.approval.ExpiresAt) {
			http.Error(w, "agent is locked or awaiting approval", 423)
			return
		}
		check, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		state, e := a.client.Status(check, in.RequestID)
		if e != nil || state.Status != "approved" || !time.Now().Before(state.ExpiresAt) {
			a.drop(in.RequestID)
			http.Error(w, "approval no longer active", 403)
			return
		}
		raw, e := vaultwire.Open(l.pending.Private, "rpc:"+in.RequestID, in.Box)
		if e != nil {
			http.Error(w, "invalid request", 403)
			return
		}
		defer clear(raw)
		var signed vaultwire.Signed
		var q vaultwire.RPC
		if json.Unmarshal(raw, &signed) != nil || vaultwire.Verify(l.approval.RequesterPublic, "rpc", signed, &q) != nil || q.RequestID != in.RequestID || len(q.Nonce) < 24 || len(q.Nonce) > 64 || !vaultwire.ValidPublic(q.ReplyPublic) || !time.Now().Before(q.ExpiresAt) || time.Until(q.ExpiresAt) > time.Minute {
			http.Error(w, "request proof rejected", 403)
			return
		}
		for nonce, end := range l.used {
			if !time.Now().Before(end) {
				delete(l.used, nonce)
			}
		}
		if _, ok := l.used[q.Nonce]; ok || len(l.used) >= 1000 {
			http.Error(w, "request already used or rate exceeded", 409)
			return
		}
		l.used[q.Nonce] = q.ExpiresAt
		result := vaultwire.RPCResult{Nonce: q.Nonce, RequestHash: vaultwire.Digest(signed.Payload)}
		result.Data, e = l.execute(q)
		if e != nil {
			result.Error = e.Error()
			result.Data = nil
		}
		response, e := vaultwire.Sign(a.client.Config.PrivateKey, "rpc-response", result)
		if e != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		b, _ := json.Marshal(response)
		defer clear(b)
		box, e := vaultwire.Seal(q.ReplyPublic, "rpc-response:"+in.RequestID+":"+q.Nonce, b)
		if e != nil {
			http.Error(w, "encryption failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(box)
	})
}
func (l *lease) execute(q vaultwire.RPC) ([]byte, error) {
	if q.Method == "ping" {
		return []byte("ready"), nil
	}
	spec := l.pending.Request
	switch q.Method {
	case "ssh":
		if spec.Kind != "ssh" || l.ring == nil || len(q.Data) < 5 || len(q.Data) > 262144 || binary.BigEndian.Uint32(q.Data[:4]) != uint32(len(q.Data)-4) || (q.Data[4] != 11 && q.Data[4] != 13) {
			return nil, errors.New("SSH operation is outside this approval")
		}
		// Block SHA-1 RSA requests. OpenSSH sends one of the SHA-2 flags.
		if q.Data[4] == 13 {
			var msg struct {
				Type  byte
				Key   []byte
				Data  []byte
				Flags uint32
			}
			if ssh.Unmarshal(q.Data[4:], &msg) != nil {
				return nil, errors.New("invalid SSH signature request")
			}
			pub, e := ssh.ParsePublicKey(msg.Key)
			if e != nil {
				return nil, e
			}
			if pub.Type() == ssh.KeyAlgoRSA && msg.Flags != uint32(agent.SignatureFlagRsaSha256) && msg.Flags != uint32(agent.SignatureFlagRsaSha512) {
				return nil, errors.New("RSA requires SHA-256 or SHA-512")
			}
		}
		left, right := net.Pipe()
		defer left.Close()
		go func() { defer right.Close(); agent.ServeAgent(l.ring, right) }()
		left.SetDeadline(time.Now().Add(5 * time.Second))
		if _, e := left.Write(q.Data); e != nil {
			return nil, e
		}
		header := make([]byte, 4)
		if _, e := io.ReadFull(left, header); e != nil {
			return nil, e
		}
		n := binary.BigEndian.Uint32(header)
		if n > 262144 {
			return nil, errors.New("SSH reply too large")
		}
		out := make([]byte, 4+int(n))
		copy(out, header)
		_, e := io.ReadFull(left, out[4:])
		return out, e
	case "age":
		if spec.Kind != "age" || l.age == nil || len(q.Data) > 65536 {
			return nil, errors.New("age operation is outside this approval")
		}
		if len(spec.Payload) > 0 {
			if l.oneShotUsed || !bytes.Equal(q.Data, spec.Payload) {
				return nil, errors.New("one-shot approval does not cover this document")
			}
			l.oneShotUsed = true
		}
		return age.DecryptHeader(q.Data, l.age)
	case "wallet-sign":
		if spec.Kind != "wallet-sign" || vaultwire.ValidateRequest(spec) != nil || !bytes.Equal(q.Data, spec.Payload) || l.oneShotUsed {
			return nil, errors.New("wallet action differs from the approved one-shot request")
		}
		if e := walletsign.CheckBinding(q.Data, spec.Identity, l.approval.IdentityID, spec.Network, l.approval.PublicKey); e != nil {
			return nil, e
		}
		l.oneShotUsed = true
		k, e := identity.EthereumKey(l.approval.Secret)
		if e != nil {
			return nil, e
		}
		defer k.D.SetInt64(0)
		defer clear(l.approval.Secret)
		return walletsign.Sign(k, q.Data)
	case "hyperliquid":
		if spec.Kind != "hyperliquid" || vaultwire.ValidateRequest(spec) != nil || !bytes.Equal(q.Data, spec.Payload) || l.oneShotUsed {
			return nil, errors.New("Hyperliquid action differs from the approved one-shot request")
		}
		if e := hyperliquid.CheckBinding(q.Data, spec.Network, l.approval.PublicKey); e != nil {
			return nil, e
		}
		l.oneShotUsed = true
		k, e := identity.EthereumKey(l.approval.Secret)
		if e != nil {
			return nil, e
		}
		defer k.D.SetInt64(0)
		defer clear(l.approval.Secret)
		return hyperliquid.Sign(k, q.Data)
	case "ethereum":
		if spec.Kind != "ethereum" || !bytes.Equal(q.Data, spec.Payload) || l.oneShotUsed {
			return nil, errors.New("transaction differs from the approved request")
		}
		l.oneShotUsed = true
		k, e := identity.EthereumKey(l.approval.Secret)
		if e != nil {
			return nil, e
		}
		defer k.D.SetInt64(0)
		return identity.SignEthereum(k, q.Data)
	case "bitcoin":
		if spec.Kind != "bitcoin" || !bytes.Equal(q.Data, spec.Payload) || l.oneShotUsed {
			return nil, errors.New("transaction differs from the approved request")
		}
		l.oneShotUsed = true
		k, e := identity.BitcoinKey(string(l.approval.Secret), spec.Network)
		if e != nil {
			return nil, e
		}
		defer k.Zero()
		return identity.SignBitcoin(k, q.Data, spec.Network)
	}
	return nil, errors.New("unsupported device operation")
}
