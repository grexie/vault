package cloud

import (
	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/vaultwire"
	"net/http"
)

func (s *Server) putCatalog(w http.ResponseWriter, r *http.Request, session Session, user User) {
	var in struct {
		DeviceID string             `json:"deviceId"`
		Box      vaultwire.Envelope `json:"box"`
	}
	if !decode(w, r, &in) {
		return
	}
	var d deviceRecord
	if _, e := s.store.Get(r.Context(), "devices", in.DeviceID, &d); e != nil || d.OwnerID != user.key() || d.Revoked || !validBox(in.Box) {
		fail(w, 403, "Paired device required")
		return
	}
	var old vaultwire.Envelope
	v, e := s.store.Get(r.Context(), "catalogs:"+user.key(), in.DeviceID, &old)
	if e != nil && e != cloudstore.ErrNotFound {
		fail(w, 503, "Catalog unavailable")
		return
	}
	if s.store.Put(r.Context(), "catalogs:"+user.key(), in.DeviceID, v, in.Box, nil) != nil {
		fail(w, 409, "Catalog changed; retry")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) deviceCatalog(w http.ResponseWriter, r *http.Request, d deviceRecord) {
	var b vaultwire.Envelope
	if _, e := s.store.Get(r.Context(), "catalogs:"+d.OwnerID, d.Device.ID, &b); e != nil {
		fail(w, 404, "Open Vault once to sync this device's public identity list")
		return
	}
	reply(w, 200, b)
}
