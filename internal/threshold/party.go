// Package threshold wraps the upstream CMP/FROST protocols with an n-of-n owner
// policy, signed approvals and an authenticated encrypted peer transport.
// No function in this package reconstructs a complete private key.
package threshold

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/grexie/vault/internal/vaultwire"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/pkg/taproot"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/frost"
)

type Owner struct {
	ID         string `json:"id"`
	SigningKey []byte `json:"signingKey"`
	BoxKey     []byte `json:"boxKey"`
}
type Policy struct {
	Owners []Owner `json:"owners"`
	Epoch  string  `json:"epoch"`
	Kind   string  `json:"kind"`
}

func (p Policy) Validate() error {
	if p.Kind != "ethereum" && p.Kind != "bitcoin" {
		return errors.New("threshold identities must be Ethereum or Bitcoin")
	}
	if len(p.Owners) < 2 || len(p.Owners) > 8 || len(p.Epoch) < 32 || len(p.Epoch) > 128 {
		return errors.New("n-of-n policy requires 2–8 owners and a fresh epoch")
	}
	prev := ""
	for _, o := range p.Owners {
		if o.ID != vaultwire.ID(o.SigningKey) || !vaultwire.ValidPublic(o.SigningKey) || !vaultwire.ValidPublic(o.BoxKey) || o.ID <= prev {
			return errors.New("owners must be distinct, sorted, and bound to valid public keys")
		}
		prev = o.ID
	}
	return nil
}
func (p Policy) ID() string { b, _ := json.Marshal(p); return vaultwire.Digest(b) }
func (p Policy) ids() []party.ID {
	out := []party.ID{}
	for _, o := range p.Owners {
		out = append(out, party.ID(o.ID))
	}
	return out
}
func (p Policy) owner(id string) (Owner, bool) {
	for _, o := range p.Owners {
		if o.ID == id {
			return o, true
		}
	}
	return Owner{}, false
}
func SortOwners(owners []Owner) {
	sort.Slice(owners, func(i, j int) bool { return owners[i].ID < owners[j].ID })
}

type Consent struct {
	PolicyID  string    `json:"policyId"`
	SessionID string    `json:"sessionId"`
	Mode      string    `json:"mode"`
	Digest    []byte    `json:"digest"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type Share struct {
	Policy    Policy `json:"policy"`
	OwnerID   string `json:"ownerId"`
	PublicKey []byte `json:"publicKey"`
	Data      []byte `json:"data"`
}
type Packet struct {
	To   string             `json:"to"`
	From string             `json:"from"`
	Box  vaultwire.Envelope `json:"box"`
}
type frame struct {
	SessionID string            `json:"sessionId"`
	PolicyID  string            `json:"policyId"`
	Mode      string            `json:"mode"`
	Message   *protocol.Message `json:"message,omitempty"`
	Echo      *echo             `json:"echo,omitempty"`
}
type echo struct {
	Sender string `json:"sender"`
	Round  int    `json:"round"`
	Digest string `json:"digest"`
}
type broadcast struct {
	Message   *protocol.Message
	Digest    string
	Echos     map[string]string
	Delivered bool
}
type Party struct {
	policy          Policy
	consent         Consent
	self            string
	signKey, boxKey []byte
	h               *protocol.MultiHandler
	broadcasts      map[string]*broadcast
	seen            map[string]string
	queue           []Packet
	failure         error
}

func Start(policy Policy, self string, signKey, boxKey []byte, consent Consent, approvals map[string]vaultwire.Signed, share *Share) (*Party, error) {
	if e := policy.Validate(); e != nil {
		return nil, e
	}
	owner, ok := policy.owner(self)
	if !ok {
		return nil, errors.New("owner not in policy")
	}
	pub, e := vaultwire.Public(signKey)
	if e != nil || !bytes.Equal(pub, owner.SigningKey) {
		return nil, errors.New("owner signing key mismatch")
	}
	pub, e = vaultwire.Public(boxKey)
	if e != nil || !bytes.Equal(pub, owner.BoxKey) {
		return nil, errors.New("owner encryption key mismatch")
	}
	if consent.PolicyID != policy.ID() || len(consent.SessionID) < 32 || len(consent.SessionID) > 128 || (consent.Mode != "create" && consent.Mode != "sign") || !time.Now().Before(consent.ExpiresAt) || consent.ExpiresAt.After(time.Now().Add(20*time.Minute)) {
		return nil, errors.New("invalid threshold ceremony")
	}
	if consent.Mode == "sign" && len(consent.Digest) != 32 || consent.Mode == "create" && len(consent.Digest) != 0 {
		return nil, errors.New("invalid threshold digest")
	}
	if len(approvals) != len(policy.Owners) {
		return nil, errors.New("every delegated owner must approve")
	}
	want, _ := json.Marshal(consent)
	for _, o := range policy.Owners {
		var got Consent
		a, ok := approvals[o.ID]
		if !ok || vaultwire.Verify(o.SigningKey, "threshold-consent", a, &got) != nil {
			return nil, errors.New("missing or invalid owner approval")
		}
		b, _ := json.Marshal(got)
		if !bytes.Equal(b, want) {
			return nil, errors.New("owners approved different operations")
		}
	}
	ids := policy.ids()
	var start protocol.StartFunc
	if consent.Mode == "create" {
		if share != nil {
			return nil, errors.New("new generation cannot import a full key or share")
		}
		if policy.Kind == "ethereum" {
			start = cmp.Keygen(curve.Secp256k1{}, party.ID(self), ids, len(ids)-1, nil)
		} else {
			start = frost.KeygenTaproot(party.ID(self), ids, len(ids)-1)
		}
	} else {
		if share == nil || share.Policy.ID() != policy.ID() || share.OwnerID != self {
			return nil, errors.New("share does not belong to this owner policy")
		}
		if e = share.Validate(); e != nil {
			return nil, e
		}
		if policy.Kind == "ethereum" {
			c := cmp.EmptyConfig(curve.Secp256k1{})
			if e = c.UnmarshalBinary(share.Data); e != nil {
				return nil, e
			}
			start = cmp.Sign(c, ids, consent.Digest, nil)
		} else {
			var c frost.TaprootConfig
			if e = cbor.Unmarshal(share.Data, &c); e != nil {
				return nil, e
			}
			start = frost.SignTaproot(&c, ids, consent.Digest)
		}
	}
	// Upstream SSID is committed to the complete owner policy, requested digest,
	// action, expiry and a fresh ceremony nonce.
	session := sha256.Sum256(want)
	h, e := protocol.NewMultiHandler(start, session[:])
	if e != nil {
		return nil, e
	}
	return &Party{policy: policy, consent: consent, self: self, signKey: append([]byte(nil), signKey...), boxKey: append([]byte(nil), boxKey...), h: h, broadcasts: map[string]*broadcast{}, seen: map[string]string{}}, nil
}
func (s *Share) Validate() error {
	if e := s.Policy.Validate(); e != nil {
		return e
	}
	if _, ok := s.Policy.owner(s.OwnerID); !ok {
		return errors.New("invalid share owner")
	}
	if len(s.Data) == 0 || len(s.Data) > 4*1024*1024 {
		return errors.New("invalid share size")
	}
	ids := s.Policy.ids()
	if s.Policy.Kind == "ethereum" {
		c := cmp.EmptyConfig(curve.Secp256k1{})
		if e := c.UnmarshalBinary(s.Data); e != nil {
			return e
		}
		if string(c.ID) != s.OwnerID || c.Threshold != len(ids)-1 || len(c.Public) != len(ids) || c.ECDSA == nil || c.ECDSA.IsZero() {
			return errors.New("share quorum mismatch")
		}
		for _, id := range ids {
			if c.Public[id] == nil {
				return errors.New("share owner set mismatch")
			}
		}
		public, e := c.PublicPoint().MarshalBinary()
		if e != nil || !bytes.Equal(public, s.PublicKey) {
			return errors.New("share public key mismatch")
		}
	} else {
		var c frost.TaprootConfig
		if e := cbor.Unmarshal(s.Data, &c); e != nil {
			return e
		}
		if string(c.ID) != s.OwnerID || c.Threshold != len(ids)-1 || len(c.VerificationShares) != len(ids) || c.PrivateShare == nil || c.PrivateShare.IsZero() {
			return errors.New("share quorum mismatch")
		}
		for _, id := range ids {
			if c.VerificationShares[id] == nil {
				return errors.New("share owner set mismatch")
			}
		}
		if !bytes.Equal(c.PublicKey, s.PublicKey) || len(s.PublicKey) != 32 {
			return errors.New("share public key mismatch")
		}
	}
	return nil
}
func (p *Party) context(to string) string {
	return "threshold:" + p.policy.ID() + ":" + p.consent.SessionID + ":" + to
}
func (p *Party) send(to string, f frame) error {
	signed, e := vaultwire.Sign(p.signKey, "threshold-message", f)
	if e != nil {
		return e
	}
	b, e := json.Marshal(signed)
	if e != nil {
		return e
	}
	for _, o := range p.policy.Owners {
		if o.ID == p.self || to != "" && o.ID != to {
			continue
		}
		box, e := vaultwire.Seal(o.BoxKey, p.context(o.ID), b)
		if e != nil {
			return e
		}
		p.queue = append(p.queue, Packet{To: o.ID, From: p.self, Box: box})
	}
	return nil
}
func (p *Party) base() frame {
	return frame{SessionID: p.consent.SessionID, PolicyID: p.policy.ID(), Mode: p.consent.Mode}
}
func slot(sender string, round int) string { return fmt.Sprintf("%s/%d", sender, round) }
func (p *Party) getBroadcast(sender string, round int) *broadcast {
	k := slot(sender, round)
	b := p.broadcasts[k]
	if b == nil {
		b = &broadcast{Echos: map[string]string{}}
		p.broadcasts[k] = b
	}
	return b
}
func (p *Party) registerBroadcast(sender string, m *protocol.Message) error {
	raw, _ := json.Marshal(m)
	digest := vaultwire.Digest(raw)
	b := p.getBroadcast(sender, int(m.RoundNumber))
	if b.Digest != "" && b.Digest != digest {
		return errors.New("owner equivocated on a broadcast")
	}
	b.Message = m
	b.Digest = digest
	b.Echos[p.self] = digest
	f := p.base()
	f.Echo = &echo{Sender: sender, Round: int(m.RoundNumber), Digest: digest}
	if e := p.send("", f); e != nil {
		return e
	}
	return p.deliver(b)
}
func (p *Party) deliver(b *broadcast) error {
	if b.Message == nil || b.Delivered {
		return nil
	}
	for _, o := range p.policy.Owners {
		d, ok := b.Echos[o.ID]
		if !ok {
			return nil
		}
		if d != b.Digest {
			return errors.New("broadcast disagreement between owners")
		}
	}
	b.Delivered = true
	if string(b.Message.From) != p.self {
		p.h.Accept(b.Message)
	}
	return nil
}
func (p *Party) Drain() ([]Packet, error) {
	if p.failure != nil {
		return nil, p.failure
	}
	if !time.Now().Before(p.consent.ExpiresAt) {
		p.Close()
		return nil, errors.New("threshold ceremony expired")
	}
	for {
		select {
		case m, ok := <-p.h.Listen():
			if !ok {
				out := p.queue
				p.queue = nil
				return out, nil
			}
			if m == nil {
				continue
			}
			f := p.base()
			f.Message = m
			if e := p.send(string(m.To), f); e != nil {
				p.failure = e
				return nil, e
			}
			if m.Broadcast {
				if e := p.registerBroadcast(p.self, m); e != nil {
					p.failure = e
					return nil, e
				}
			}
		default:
			out := p.queue
			p.queue = nil
			return out, nil
		}
	}
}
func (p *Party) Accept(packet Packet) error {
	if p.failure != nil {
		return p.failure
	}
	if !time.Now().Before(p.consent.ExpiresAt) {
		return errors.New("threshold ceremony expired")
	}
	e := p.accept(packet)
	if e != nil {
		p.failure = e
		p.h = nil
	}
	return e
}
func (p *Party) accept(packet Packet) error {
	owner, ok := p.policy.owner(packet.From)
	if !ok || packet.To != p.self || packet.From == p.self {
		return errors.New("invalid threshold peer")
	}
	raw, e := vaultwire.Open(p.boxKey, p.context(p.self), packet.Box)
	if e != nil {
		return errors.New("threshold envelope rejected")
	}
	defer clear(raw)
	var signed vaultwire.Signed
	if json.Unmarshal(raw, &signed) != nil {
		return errors.New("invalid threshold envelope")
	}
	var f frame
	if e = vaultwire.Verify(owner.SigningKey, "threshold-message", signed, &f); e != nil {
		return e
	}
	if f.SessionID != p.consent.SessionID || f.PolicyID != p.policy.ID() || f.Mode != p.consent.Mode || (f.Message == nil) == (f.Echo == nil) {
		return errors.New("threshold transcript mismatch")
	}
	if f.Echo != nil {
		if _, ok = p.policy.owner(f.Echo.Sender); !ok || f.Echo.Round < 0 || f.Echo.Round > 20 || len(f.Echo.Digest) != 64 {
			return errors.New("invalid broadcast acknowledgment")
		}
		b := p.getBroadcast(f.Echo.Sender, f.Echo.Round)
		if old := b.Echos[packet.From]; old != "" && old != f.Echo.Digest {
			return errors.New("owner equivocated on acknowledgment")
		}
		b.Echos[packet.From] = f.Echo.Digest
		return p.deliver(b)
	}
	m := f.Message
	if string(m.From) != packet.From || !m.IsFor(party.ID(p.self)) || len(m.Data) > 4*1024*1024 || len(m.SSID) == 0 {
		return errors.New("protocol message sender or recipient mismatch")
	}
	key := fmt.Sprintf("%s/%d/%t", m.From, m.RoundNumber, m.Broadcast)
	digest := vaultwire.Digest(signed.Payload)
	if old := p.seen[key]; old != "" {
		if old != digest {
			return errors.New("conflicting protocol message")
		}
		return nil
	}
	p.seen[key] = digest
	if m.Broadcast {
		return p.registerBroadcast(packet.From, m)
	}
	p.h.Accept(m)
	return nil
}
func (p *Party) Result() (*Share, []byte, error) {
	if p.failure != nil {
		return nil, nil, p.failure
	}
	result, e := p.h.Result()
	if e != nil {
		return nil, nil, e
	}
	if p.consent.Mode == "create" {
		s := &Share{Policy: p.policy, OwnerID: p.self}
		if c, ok := result.(*cmp.Config); ok {
			s.Data, e = c.MarshalBinary()
			if e == nil {
				s.PublicKey, e = c.PublicPoint().MarshalBinary()
			}
		} else if c, ok := result.(*frost.TaprootConfig); ok {
			s.Data, e = cbor.Marshal(c)
			s.PublicKey = append([]byte(nil), c.PublicKey...)
		} else {
			return nil, nil, errors.New("unexpected threshold result")
		}
		if e != nil {
			return nil, nil, e
		}
		if e = s.Validate(); e != nil {
			return nil, nil, e
		}
		return s, nil, nil
	}
	switch sig := result.(type) {
	case *ecdsa.Signature:
		b, e := sig.SigEthereum()
		return nil, b, e
	case taproot.Signature:
		return nil, append([]byte(nil), sig...), nil
	default:
		return nil, nil, errors.New("unexpected threshold signature")
	}
}

// Close drops the pure in-memory protocol state. The pinned upstream Stop
// implementation cannot safely be called after completion (it closes twice).
// Peers time out instead of receiving an unauthenticated abort.
func (p *Party) Close() {
	if p.h != nil {
		p.h = nil
	}
	clear(p.signKey)
	clear(p.boxKey)
	p.failure = errors.New("threshold ceremony closed")
}
