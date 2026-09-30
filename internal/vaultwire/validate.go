package vaultwire

import (
	"encoding/json"
	"errors"
)

// ValidateRequest is shared by the API and the browser worker. A review for one
// operation must never authorize a different class of identity or a raw key export.
func ValidateRequest(q Request) error {
	crypto := q.IdentityType == "ssh" || q.IdentityType == "ethereum" || q.IdentityType == "bitcoin"
	credential := q.IdentityType == "aws" || q.IdentityType == "github" || q.IdentityType == "cloudflare" || q.IdentityType == "docker" || q.IdentityType == "credentials"
	valid := false
	switch q.Kind {
	case "ssh", "age":
		valid = q.IdentityType == "ssh" && q.Managed
	case "ethereum", "bitcoin":
		valid = q.IdentityType == q.Kind && q.Managed
	case "create":
		valid = crypto
	case "import":
		valid = crypto || credential || q.IdentityType == "login" || q.IdentityType == "payment-card"
	case "lookup":
		valid = crypto || credential || q.IdentityType == "login" || q.IdentityType == "payment-card" || q.IdentityType == ""
	case "keychain-import":
		valid = q.IdentityType == "login"
	case "credentials", "api":
		var inv Invocation
		valid = credential && json.Unmarshal(q.Payload, &inv) == nil && inv.Provider != "" && (q.IdentityType == inv.Provider || q.IdentityType == "credentials" && q.Network == inv.Provider)
	case "autofill":
		var inv struct {
			Provider string `json:"provider"`
		}
		valid = (q.IdentityType == "login" || q.IdentityType == "payment-card") && json.Unmarshal(q.Payload, &inv) == nil && inv.Provider == q.IdentityType
	}
	if !valid {
		return errors.New("request operation and identity type do not match, or require a managed signing device")
	}
	return nil
}
