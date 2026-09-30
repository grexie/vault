package device

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/vaultwire"
	"time"
)

func (c *Client) Catalog(ctx context.Context) ([]identity.Record, error) {
	var box vaultwire.Envelope
	if e := c.Call(ctx, "/api/v1/device/catalog", struct{}{}, &box); e != nil {
		return nil, e
	}
	b, e := vaultwire.Open(c.Config.BoxPrivate, "catalog:"+c.Config.Device.ID, box)
	if e != nil {
		return nil, errors.New("public identity catalog could not be opened")
	}
	defer clear(b)
	var signed vaultwire.Signed
	var catalog struct {
		OwnerID    string            `json:"ownerId"`
		Identities []identity.Record `json:"identities"`
		UpdatedAt  string            `json:"updatedAt"`
	}
	if json.Unmarshal(b, &signed) != nil || vaultwire.Verify(c.Config.OwnerPublic, "catalog", signed, &catalog) != nil || catalog.OwnerID != c.Config.OwnerID {
		return nil, errors.New("public identity catalog owner signature rejected")
	}
	for _, r := range catalog.Identities {
		if len(r.Secret) != 0 {
			return nil, errors.New("catalog must not contain private identity data")
		}
	}
	return catalog.Identities, nil
}
func (c *Client) Authorization(p Pending, state vaultwire.RequestState) (vaultwire.Authorization, vaultwire.Receiver, error) {
	var a vaultwire.Authorization
	var recv vaultwire.Receiver
	if state.Status != "approved" || state.Authorization == nil || state.Receiver == nil || vaultwire.Verify(c.Config.OwnerPublic, "authorization", *state.Authorization, &a) != nil || !time.Now().Before(a.ExpiresAt) || time.Until(a.ExpiresAt) > time.Duration(p.Request.Duration)*time.Second || a.RequestID != p.Request.ID || a.RequestHash != vaultwire.Digest(p.Signed.Payload) || a.ReceiverHash != vaultwire.Digest(state.Receiver.Payload) || vaultwire.ID(a.AgentPublic) != p.Request.AgentID {
		return a, recv, errors.New("owner authorization does not match this request")
	}
	if vaultwire.Verify(a.AgentPublic, "receiver", *state.Receiver, &recv) != nil || recv.RequestID != p.Request.ID || recv.RequestHash != a.RequestHash {
		return a, recv, errors.New("agent receiver signature rejected")
	}
	return a, recv, nil
}
