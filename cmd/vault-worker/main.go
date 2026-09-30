//go:build js && wasm

package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"syscall/js"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/grexie/vault/internal/backup"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/provider"
	"github.com/grexie/vault/internal/threshold"
	"github.com/grexie/vault/internal/vaultwire"
)

type input struct {
	Action    string `json:"action"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Network   string `json:"network"`
	Key       string `json:"key"`
	Password  string `json:"password"`
	Data      string `json:"data"`
	ABI       string `json:"abi"`
	PublicKey string `json:"publicKey"`
}

func operation(in input) (any, error) {
	switch in.Action {
	case "validate-request":
		var q vaultwire.Request
		if json.Unmarshal([]byte(in.Data), &q) != nil {
			return nil, errors.New("invalid request")
		}
		return true, vaultwire.ValidateRequest(q)

	case "providers":
		return provider.Builtins(), nil
	case "validate":
		var r identity.Record
		if json.Unmarshal([]byte(in.Data), &r) != nil {
			return nil, errors.New("invalid identity")
		}
		if e := identity.Validate(r); e != nil {
			return nil, e
		}
		return r, nil
	case "generate":
		return identity.Generate(in.Name, in.Type, in.Network)
	case "import":
		return identity.Import(in.Name, in.Type, in.Network, []byte(in.Key), []byte(in.Password))
	case "review-ethereum":
		return identity.ReviewEthereum([]byte(in.Data))
	case "decode-abi":
		b, e := hex.DecodeString(strings.TrimPrefix(in.Data, "0x"))
		if e != nil {
			return nil, e
		}
		return identity.DecodeABI([]byte(in.ABI), b)
	case "review-bitcoin":
		b, e := base64.StdEncoding.DecodeString(in.Data)
		if e != nil {
			return nil, e
		}
		var pub *btcec.PublicKey
		if in.PublicKey != "" {
			p, e := hex.DecodeString(in.PublicKey)
			if e != nil {
				return nil, e
			}
			pub, e = btcec.ParsePubKey(p)
			if e != nil {
				return nil, e
			}
		}
		return identity.ReviewBitcoin(b, in.Network, pub)
	case "backup-encrypt":
		b, e := backup.Encrypt([]byte(in.Password), []byte(in.Data))
		if e != nil {
			return nil, e
		}
		return string(b), nil
	case "backup-decrypt":
		b, e := backup.Decrypt([]byte(in.Password), []byte(in.Data))
		if e != nil {
			return nil, e
		}
		defer clear(b)
		var data struct {
			Version    int               `json:"version"`
			Identities []identity.Record `json:"identities"`
		}
		if json.Unmarshal(b, &data) != nil || data.Version != 1 || len(data.Identities) > 1000 {
			return nil, errors.New("invalid identity backup")
		}
		seen := map[string]bool{}
		for _, r := range data.Identities {
			if seen[r.ID] || r.ID == "" {
				return nil, errors.New("duplicate or missing identity ID")
			}
			seen[r.ID] = true
			if r.Threshold {
				var share threshold.Share
				if json.Unmarshal(r.Secret, &share) != nil {
					return nil, errors.New("invalid threshold share")
				}
				if e = share.Validate(); e != nil {
					return nil, e
				}
			} else if e = identity.Validate(r); e != nil {
				return nil, e
			}
		}
		return data, nil
	default:
		return nil, errors.New("unknown browser worker operation")
	}
}
func main() {
	js.Global().Set("vaultOperation", js.FuncOf(func(this js.Value, args []js.Value) any {
		result := map[string]any{}
		if len(args) != 1 {
			result["error"] = "Invalid worker request"
		} else {
			var in input
			if json.Unmarshal([]byte(args[0].String()), &in) != nil {
				result["error"] = "Invalid worker data"
			} else {
				value, e := operation(in)
				if e != nil {
					result["error"] = e.Error()
				} else {
					result["result"] = value
				}
			}
		}
		b, _ := json.Marshal(result)
		return string(b)
	}))
	js.Global().Call("postMessage", map[string]any{"ready": true})
	select {}
}
