package cloud

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/vaultwire"
)

// Only public request selectors reach the server; key material remains inside
// the browser-encrypted vault. A deletion also revokes default-name requests.
type identityRevocation struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Network string `json:"network,omitempty"`
}

func validRevocations(items []identityRevocation) bool {
	if len(items) > 64 {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item.Name) == "" || len(item.Name) > 80 || len(item.Network) > 80 || strings.ContainsAny(item.Name+item.Network, "\x00\r\n") {
			return false
		}
		switch item.Type {
		case "ssh", "ethereum", "bitcoin", "aws", "github", "cloudflare", "docker", "credentials", "login", "payment-card":
		default:
			return false
		}
	}
	return true
}

// Caller holds vaultMutation until its vault write or approval is complete.
func (s *Server) requireVaultVersion(w http.ResponseWriter, r *http.Request, user User, expected int64) bool {
	var record VaultRecord
	current, err := s.store.Get(r.Context(), "vaults", user.key(), &record)
	if errors.Is(err, cloudstore.ErrNotFound) {
		current = 0
	} else if err != nil {
		fail(w, 503, "Encrypted storage unavailable")
		return false
	}
	if current != expected || expected < 0 {
		fail(w, 409, "Your vault changed on another device. Reload before continuing.")
		return false
	}
	return true
}

func matchesRevocation(q vaultwire.Request, items []identityRevocation) bool {
	for _, item := range items {
		if q.IdentityType == item.Type && (q.Identity == "" || q.Identity == item.Name) && (item.Type != "credentials" || item.Network == q.Network) {
			return true
		}
	}
	return false
}

func (s *Server) revokeIdentityRequests(r *http.Request, user User, items []identityRevocation) error {
	if len(items) == 0 {
		return nil
	}
	scope := "requests:" + user.key()
	docs, err := s.store.List(r.Context(), scope)
	if err != nil {
		return err
	}
	for _, doc := range docs {
		var state vaultwire.RequestState
		if err = s.store.Open(doc, &state); errors.Is(err, cloudstore.ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}
		var spec vaultwire.Request
		if err = json.Unmarshal(state.Signed.Payload, &spec); err != nil {
			return err
		}
		if !matchesRevocation(spec, items) {
			continue
		}
		// An agent may publish a receiver concurrently. Retry that CAS conflict;
		// never delete the identity unless all matching live access was revoked.
		for attempt := 0; ; attempt++ {
			version, getErr := s.store.Get(r.Context(), scope, state.ID, &state)
			if errors.Is(getErr, cloudstore.ErrNotFound) {
				break
			}
			if getErr != nil {
				return getErr
			}
			if state.Status != "pending" && state.Status != "approved" {
				break
			}
			state.Status = "revoked"
			state.Box, state.Response, state.Authorization = nil, nil, nil
			state.ExpiresAt = time.Now().Add(time.Hour)
			err = s.store.Put(r.Context(), scope, state.ID, version, state, &state.ExpiresAt)
			if errors.Is(err, cloudstore.ErrConflict) && attempt < 4 {
				continue
			}
			if err != nil {
				return err
			}
			break
		}
	}
	return nil
}
