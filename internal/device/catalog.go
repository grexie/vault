package device

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/vaultwire"
	"time"
)

type PublicCatalog struct {
	OwnerID           string                       `json:"ownerId"`
	Identities        []identity.Record            `json:"identities"`
	WalletPermissions []vaultwire.WalletPermission `json:"walletPermissions,omitempty"`
	UpdatedAt         string                       `json:"updatedAt"`
}

func (c *Client) Catalog(ctx context.Context) ([]identity.Record, error) {
	catalog, e := c.CatalogData(ctx)
	return catalog.Identities, e
}
func (c *Client) CatalogData(ctx context.Context) (PublicCatalog, error) {
	var box vaultwire.Envelope
	if e := c.Call(ctx, "/api/v1/device/catalog", struct{}{}, &box); e != nil {
		return PublicCatalog{}, e
	}
	b, e := vaultwire.Open(c.Config.BoxPrivate, "catalog:"+c.Config.Device.ID, box)
	if e != nil {
		return PublicCatalog{}, errors.New("public identity catalog could not be opened")
	}
	defer clear(b)
	var signed vaultwire.Signed
	var catalog PublicCatalog
	if json.Unmarshal(b, &signed) != nil || vaultwire.Verify(c.Config.OwnerPublic, "catalog", signed, &catalog) != nil || catalog.OwnerID != c.Config.OwnerID {
		return PublicCatalog{}, errors.New("public identity catalog owner signature rejected")
	}
	for _, r := range catalog.Identities {
		if len(r.Secret) != 0 {
			return PublicCatalog{}, errors.New("catalog must not contain private identity data")
		}
	}
	return catalog, nil
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
