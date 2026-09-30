// Package walletsign binds website context and submission consent to every
// one-shot signature. It is used by the browser reviewer and private signer.
package walletsign

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/hyperliquid"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/vaultwire"
)

type Payload struct {
	Origin     string          `json:"origin"`
	IdentityID string          `json:"identityId"`
	Identity   string          `json:"identity"`
	Address    string          `json:"address"`
	ChainID    string          `json:"chainId"`
	Method     string          `json:"method"`
	Data       json.RawMessage `json:"data"`
	Submit     bool            `json:"submit"`
	RPCURL     string          `json:"rpcUrl"`
}

func Decode(raw []byte) (Payload, error) {
	p := Payload{}
	v, e := StrictJSON(raw)
	if e != nil {
		return p, e
	}
	m, ok := v.(map[string]any)
	if !ok || len(m) != 9 || exact(m, "origin", "identityId", "identity", "address", "chainId", "method", "data", "submit", "rpcUrl") != nil {
		return p, errors.New("invalid wallet signing envelope")
	}
	if json.Unmarshal(raw, &p) != nil || len(p.IdentityID) < 1 || len(p.IdentityID) > 100 || len(p.Identity) < 1 || len(p.Identity) > 80 || len(p.Address) != 42 || !common.IsHexAddress(p.Address) {
		return p, errors.New("invalid wallet signing identity")
	}
	if e = vaultwire.WalletOrigin(p.Origin); e != nil {
		return p, e
	}
	if _, e = vaultwire.WalletChainID(p.ChainID); e != nil {
		return p, e
	}
	switch p.Method {
	case "eth_signTransaction", "eth_sendTransaction":
		if e := vaultwire.WalletURL(p.RPCURL, true); e != nil {
			return p, e
		}
		if p.Submit != (p.Method == "eth_sendTransaction") {
			return p, errors.New("broadcast intent differs from wallet method")
		}
		a, e := identity.DecodeEthereum(p.Data)
		if e != nil {
			return p, e
		}
		chain, _ := vaultwire.WalletChainID(p.ChainID)
		if a.From != common.HexToAddress(p.Address) || a.ChainID == nil || a.ChainID.ToInt().Cmp(chain) != 0 {
			return p, errors.New("transaction differs from wallet identity or chain")
		}
		if _, e = a.Transaction(); e != nil {
			return p, e
		}
	case "personal_sign", "eth_sign", "eth_signTypedData", "eth_signTypedData_v1", "eth_signTypedData_v3", "eth_signTypedData_v4":
		if p.Submit || p.RPCURL != "" {
			return p, errors.New("messages cannot authorize transaction submission or RPC access")
		}
		if _, e = p.Digest(); e != nil {
			return p, e
		}
	default:
		return p, errors.New("unsupported wallet signing method")
	}
	return p, nil
}
func (p Payload) Digest() ([]byte, error) {
	switch p.Method {
	case "personal_sign", "eth_sign":
		var value any
		if json.Unmarshal(p.Data, &value) != nil {
			return nil, errors.New("message must be hexadecimal bytes")
		}
		b, e := hexBytes(value)
		if e != nil {
			return nil, e
		}
		return crypto.Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(b))), b), nil
	case "eth_signTypedData", "eth_signTypedData_v1":
		return LegacyHash(p.Data)
	case "eth_signTypedData_v3":
		return TypedHash(p.Data, 3)
	case "eth_signTypedData_v4":
		return TypedHash(p.Data, 4)
	case "eth_signTransaction", "eth_sendTransaction":
		r, e := identity.ReviewEthereum(p.Data)
		if e != nil {
			return nil, e
		}
		return hex.DecodeString(strings.TrimPrefix(r.Digest, "0x"))
	}
	return nil, errors.New("unsupported wallet method")
}
func CheckBinding(raw []byte, name, id, network, publicKey string) error {
	p, e := Decode(raw)
	if e != nil {
		return e
	}
	a, e := hyperliquid.PublicAddress(publicKey)
	if e != nil {
		return e
	}
	if p.Identity != name || id != "" && p.IdentityID != id || p.ChainID != network || !strings.EqualFold(a, p.Address) {
		return errors.New("wallet approval identity or chain mismatch")
	}
	return nil
}
func Sign(key *ecdsa.PrivateKey, raw []byte) ([]byte, error) {
	p, e := Decode(raw)
	if e != nil {
		return nil, e
	}
	if crypto.PubkeyToAddress(key.PublicKey) != common.HexToAddress(p.Address) {
		return nil, errors.New("wallet key differs from the reviewed signer")
	}
	if p.Method == "eth_signTransaction" || p.Method == "eth_sendTransaction" {
		return identity.SignEthereum(key, p.Data)
	}
	h, e := p.Digest()
	if e != nil {
		return nil, e
	}
	s, e := crypto.Sign(h, key)
	if e == nil {
		s[64] += 27
	}
	return s, e
}
func Verify(raw, sig []byte, publicKey string) error {
	p, e := Decode(raw)
	if e != nil {
		return e
	}
	a, e := hyperliquid.PublicAddress(publicKey)
	if e != nil || !strings.EqualFold(a, p.Address) {
		return errors.New("wallet authorization public key mismatch")
	}
	if p.Method == "eth_signTransaction" || p.Method == "eth_sendTransaction" {
		_, e := identity.VerifyEthereum(p.Data, sig)
		return e
	}
	if len(sig) != 65 || sig[64] < 27 || sig[64] > 28 {
		return errors.New("invalid wallet signature")
	}
	b := append([]byte{}, sig...)
	b[64] -= 27
	h, e := p.Digest()
	if e != nil {
		return e
	}
	pub, e := crypto.SigToPub(h, b)
	if e != nil || crypto.PubkeyToAddress(*pub) != common.HexToAddress(a) {
		return errors.New("wallet signature does not match the approved message")
	}
	return nil
}
func Review(raw []byte) (identity.Review, error) {
	p, e := Decode(raw)
	if e != nil {
		return identity.Review{}, e
	}
	r := identity.Review{Kind: "wallet-sign", Title: "Sign a website message", Fields: []identity.Field{{Label: "Website", Value: p.Origin}, {Label: "Vault identity", Value: p.Identity}, {Label: "Ethereum address", Value: p.Address}, {Label: "Connected chain", Value: p.ChainID}, {Label: "Signing method", Value: p.Method}}, Warnings: []string{}}
	if p.Method == "eth_signTransaction" || p.Method == "eth_sendTransaction" {
		tx, e := identity.ReviewEthereum(p.Data)
		if e != nil {
			return r, e
		}
		r.Fields = append(r.Fields, identity.Field{Label: "Approved chain RPC", Value: p.RPCURL})
		r.Title = tx.Title
		r.Fields = append(r.Fields, tx.Fields...)
		r.Warnings = tx.Warnings
		r.Digest = tx.Digest
		r.Raw = string(p.Data)
		if p.Submit {
			r.Fields = append(r.Fields, identity.Field{Label: "Action", Value: "Sign and submit this transaction"})
			r.Warnings = append(r.Warnings, "Approving will sign and submit this transaction. This approval covers only this exact transaction.")
		} else {
			r.Fields = append(r.Fields, identity.Field{Label: "Action", Value: "Sign only; return signed transaction to the website"})
		}
		return r, nil
	}
	h, e := p.Digest()
	if e != nil {
		return r, e
	}
	r.Digest = "0x" + hex.EncodeToString(h)
	r.Raw = string(p.Data)
	if p.Method == "personal_sign" || p.Method == "eth_sign" {
		var s string
		_ = json.Unmarshal(p.Data, &s)
		b, _ := hexBytes(s)
		message := s
		if utf8.Valid(b) {
			message = string(b)
		}
		r.Fields = append(r.Fields, identity.Field{Label: "Message", Value: message}, identity.Field{Label: "Exact message bytes", Value: s})
		r.Warnings = append(r.Warnings, "A message signature can authorize login, orders, or other actions. The website's text is not a guarantee of its effects. This method uses Ethereum's signed-message prefix.")
	} else {
		r.Title = "Sign website typed data"

		r.Warnings = append(r.Warnings, "Structured data can authorize token spending, transfers, orders, or permissions. Review every field; names supplied by the website do not establish safety.")
		if p.Method == "eth_signTypedData" || p.Method == "eth_signTypedData_v1" {
			r.Fields = append(r.Fields, identity.Field{Label: "Legacy typed fields", Value: string(p.Data)})
			r.Warnings = append(r.Warnings, "Legacy typed data v1 has no enforced chain or verifying-contract domain separation.")
		} else {
			version := 4
			if p.Method == "eth_signTypedData_v3" {
				version = 3
			}
			t, _ := parseTyped(p.Data, version)
			ignored := []string{}
			declared := map[string]any{"primaryType": t.Primary, "types": json.RawMessage("{}"), "domain": t.project("EIP712Domain", t.Domain, "domain", &ignored, 0), "message": t.project(t.Primary, t.Message, "message", &ignored, 0)}
			delete(declared, "types")
			if t.Primary == "EIP712Domain" {
				delete(declared, "message")
				if len(t.Message) > 0 {
					ignored = append(ignored, "message (entire message is unsigned for a domain-only signature)")
				}
			}

			shown, _ := json.MarshalIndent(declared, "", "  ")
			r.Fields = append(r.Fields, identity.Field{Label: "Declared signed fields", Value: string(shown)})
			if len(ignored) > 0 {
				r.Warnings = append(r.Warnings, "Unsigned metadata is excluded from this signature: "+strings.Join(ignored, ", ")+". Only the declared fields above are signed.")
			}
			if strings.Contains(t.Primary, "ApproveAgent") {
				r.Title = "Authorize a Hyperliquid trading wallet"
				r.Warnings = append(r.Warnings, "This grants a separate API wallet trading authority on Hyperliquid. It survives this Vault approval and must be revoked on Hyperliquid. It is more than a website login.")
			}
			if strings.Contains(t.Primary, "ApproveBuilderFee") {
				r.Title = "Approve Hyperliquid builder fees"
				r.Warnings = append(r.Warnings, "This grants a persistent builder fee allowance on Hyperliquid, including future orders.")
			}
			if t.Primary == "Hyperliquid:AcceptTerms" {
				r.Title = "Accept Hyperliquid terms"
			}

			for _, n := range []string{"name", "version", "chainId", "verifyingContract", "salt"} {
				if v, ok := declared["domain"].(map[string]any)[n]; ok {
					r.Fields = append(r.Fields, identity.Field{Label: "Domain " + n, Value: fmt.Sprint(v)})
				}
			}
			if chain, ok := declared["domain"].(map[string]any)["chainId"]; ok {
				n, e := parseInteger(chain)
				want, _ := vaultwire.WalletChainID(p.ChainID)
				if e != nil || n.Cmp(want) != 0 {
					r.Warnings = append(r.Warnings, "The signing domain chain differs from the connected chain. Some protocols use a separate signing domain; verify that this is intended.")
				}
			} else {
				r.Warnings = append(r.Warnings, "This signature is not bound to a chain in its typed domain.")
			}
		}
	}
	r.Fields = append(r.Fields, identity.Field{Label: "Raw signing hash", Value: r.Digest})
	r.Warnings = append(r.Warnings, "Revoking Vault access cannot recall a signature already returned to this website.")
	return r, nil
}
