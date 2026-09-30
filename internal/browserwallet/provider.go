//go:build unix

package browserwallet

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/foundry"
	"github.com/grexie/vault/internal/hyperliquid"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/vaultwire"
	"github.com/grexie/vault/internal/walletsign"
)

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

type Backend interface {
	Catalog(context.Context) (device.PublicCatalog, error)
	Control(context.Context, vaultwire.WalletControl) (vaultwire.WalletControlResult, error)
	Sign(context.Context, walletsign.Payload) ([]byte, error)
	DeviceID() string
}
type rate struct {
	Start time.Time
	Count int
}
type Bridge struct {
	Backend  Backend
	VaultURL string
	Store    Store
	mu       sync.Mutex
	pending  map[string]bool
	rates    map[string]rate
	signMu   sync.Mutex
}

func New(b Backend, s Store) *Bridge {
	return &Bridge{Backend: b, VaultURL: "https://vault.grexie.com/app/", Store: s, pending: map[string]bool{}, rates: map[string]rate{}}
}
func (b *Bridge) permission(ctx context.Context, origin string) (*vaultwire.WalletPermission, error) {
	c, e := b.Backend.Catalog(ctx)
	if e != nil {
		return nil, &Error{4900, "Vault catalogue unavailable"}
	}
	site, e := b.Store.site(origin)
	if e != nil {
		return nil, e
	}
	for _, p := range c.WalletPermissions {
		if p.DeviceID != b.Backend.DeviceID() || p.Origin != origin || p.ID == site.RevokedID {
			continue
		}
		for _, r := range c.Identities {
			if r.ID == p.IdentityID && r.Name == p.Identity && r.Type == "ethereum" && !r.Threshold && strings.EqualFold(r.Address, p.Address) && r.PublicKey == p.PublicKey {
				addr, e := hyperliquid.PublicAddress(r.PublicKey)
				if e == nil && strings.EqualFold(addr, p.Address) {
					return &p, nil
				}
			}
		}
	}
	return nil, nil
}
func permissionView(origin string, p *vaultwire.WalletPermission) []any {
	if p == nil {
		return []any{}
	}
	return []any{map[string]any{"id": p.ID, "invoker": origin, "parentCapability": "eth_accounts", "date": p.CreatedAt.UnixMilli(), "caveats": []any{map[string]any{"type": "restrictReturnedAccounts", "value": []string{p.Address}}}}}
}
func approvedChain(p *vaultwire.WalletPermission, id string) bool {
	if p == nil {
		return false
	}
	for _, c := range p.Chains {
		if c == id {
			return true
		}
	}
	return false
}
func (b *Bridge) limited(origin string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r := b.rates[origin]
	if time.Since(r.Start) > time.Minute {
		r = rate{Start: time.Now()}
	}
	r.Count++
	if len(b.rates) > 256 {
		for k, v := range b.rates {
			if time.Since(v.Start) > time.Minute {
				delete(b.rates, k)
			}
		}
	}
	if len(b.rates) > 512 {
		return true
	}
	b.rates[origin] = r
	return r.Count > 120
}
func (b *Bridge) begin(origin string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending[origin] {
		return &Error{-32002, "A Vault approval is already pending for this website"}
	}
	b.pending[origin] = true
	return nil
}
func (b *Bridge) end(origin string) { b.mu.Lock(); delete(b.pending, origin); b.mu.Unlock() }
func decodeParams(raw json.RawMessage) ([]json.RawMessage, error) {
	if len(raw) == 0 {
		raw = []byte("[]")
	}
	v, e := walletsign.StrictJSON(raw)
	if e != nil {
		return nil, &Error{-32602, "Invalid wallet parameters"}
	}
	if _, ok := v.([]any); !ok {
		return nil, &Error{-32602, "Wallet parameters must be an array"}
	}
	var p []json.RawMessage
	e = json.Unmarshal(raw, &p)
	return p, e
}
func controlError(e error) error {
	var pe *Error
	if errors.As(e, &pe) {
		return pe
	}
	return &Error{4001, "Vault request was rejected, cancelled, expired or unavailable"}
}

// Call accepts an origin supplied by Chrome's isolated content-script sender,
// never the page's message body. Native messaging authenticates the extension.
func (b *Bridge) Call(ctx context.Context, origin, method string, raw json.RawMessage) (any, error) {
	if e := vaultwire.WalletOrigin(origin); e != nil {
		return nil, &Error{4100, "Invalid website origin"}
	}
	if b.limited(origin) {
		return nil, &Error{-32005, "Wallet request rate limit exceeded"}
	}
	params, e := decodeParams(raw)
	if e != nil {
		return nil, e
	}
	site, e := b.Store.site(origin)
	if e != nil {
		return nil, &Error{-32603, "Local wallet settings unavailable"}
	}
	chain, e := b.Store.chain(site.ChainID)
	if e != nil {
		return nil, e
	}
	if method == "eth_chainId" {
		return chain.ChainID, nil
	}
	if method == "net_version" {
		n, _ := vaultwire.WalletChainID(chain.ChainID)
		return n.String(), nil
	}
	if readMethods[method] {
		if e = checkChain(ctx, chain); e != nil {
			return nil, e
		}
		return rpc(ctx, chain, method, params)
	}
	p, e := b.permission(ctx, origin)
	if e != nil {
		return nil, e
	}
	switch method {
	case "_state":
		return map[string]any{"connected": p != nil, "permission": p, "chain": chain, "vaultURL": b.VaultURL}, nil
	case "eth_accounts":
		if p == nil {
			return []string{}, nil
		}
		return []string{p.Address}, nil
	case "wallet_getPermissions":
		return permissionView(origin, p), nil
	case "eth_requestAccounts", "wallet_requestPermissions", "_changeIdentity":
		if method == "wallet_requestPermissions" && !accountPermissionParams(params) {
			return nil, &Error{4200, "Only eth_accounts permission is supported"}
		}
		if p == nil || method == "_changeIdentity" {
			result, e := b.control(ctx, origin, vaultwire.WalletControl{Origin: origin, Operation: "connect", Chain: chain})
			if e != nil {
				return nil, e
			}
			p = &result.Permission
		}
		if method == "wallet_requestPermissions" {
			return permissionView(origin, p), nil
		}
		return []string{p.Address}, nil
	case "wallet_revokePermissions":
		if !accountPermissionParams(params) {
			return nil, &Error{4200, "Only eth_accounts permission is supported"}
		}
		if p != nil {
			e = b.Store.update(func(s *state) error { v := s.Sites[origin]; v.RevokedID = p.ID; s.Sites[origin] = v; return nil })
		}
		return nil, e
	case "wallet_addEthereumChain":
		if len(params) != 1 {
			return nil, &Error{-32602, "One chain definition is required"}
		}
		var proposed vaultwire.WalletChain
		var obj map[string]json.RawMessage
		if json.Unmarshal(params[0], &obj) != nil {
			return nil, &Error{-32602, "Invalid chain"}
		}
		for n := range obj {
			if n != "chainId" && n != "chainName" && n != "nativeCurrency" && n != "rpcUrls" && n != "blockExplorerUrls" && n != "iconUrls" {
				return nil, &Error{-32602, "Unsupported chain field"}
			}
		}
		if json.Unmarshal(params[0], &proposed) != nil || proposed.Validate() != nil {
			return nil, &Error{-32602, "Invalid chain metadata or RPC URL"}
		}
		// EIP-3085 adding a known chain is a no-op. A site cannot replace
		// another site's approved global RPC metadata.
		if _, existingErr := b.Store.chain(proposed.ChainID); existingErr == nil {
			return nil, nil
		}
		if _, e = b.control(ctx, origin, vaultwire.WalletControl{Origin: origin, Operation: "add", Chain: proposed}); e != nil {
			return nil, e
		}
		return nil, nil
	case "wallet_switchEthereumChain":
		if len(params) != 1 {
			return nil, &Error{-32602, "One chain ID is required"}
		}
		var v map[string]string
		if json.Unmarshal(params[0], &v) != nil || len(v) != 1 {
			return nil, &Error{-32602, "Invalid chain switch"}
		}
		next, e := b.Store.chain(v["chainId"])
		if e != nil {
			return nil, e
		}
		if next.ChainID == chain.ChainID && approvedChain(p, next.ChainID) {
			return nil, nil
		}
		_, e = b.control(ctx, origin, vaultwire.WalletControl{Origin: origin, Operation: "switch", Chain: next})
		return nil, e
	}
	if p == nil {
		return nil, &Error{4100, "Connect this website before requesting a signature"}
	}
	if !approvedChain(p, chain.ChainID) {
		return nil, &Error{4100, "This chain is not approved for this website"}
	}
	switch method {
	case "personal_sign", "eth_sign", "eth_signTypedData", "eth_signTypedData_v1", "eth_signTypedData_v3", "eth_signTypedData_v4", "eth_signTransaction", "eth_sendTransaction":
		return b.sign(ctx, origin, method, params, *p, chain)
	default:
		return nil, &Error{4200, "Unsupported wallet method"}
	}
}
func accountPermissionParams(p []json.RawMessage) bool {
	if len(p) != 1 {
		return false
	}
	var m map[string]map[string]any
	return json.Unmarshal(p[0], &m) == nil && len(m) == 1 && m["eth_accounts"] != nil && len(m["eth_accounts"]) == 0
}
func (b *Bridge) control(ctx context.Context, origin string, c vaultwire.WalletControl) (vaultwire.WalletControlResult, error) {
	var empty vaultwire.WalletControlResult
	if e := b.begin(origin); e != nil {
		return empty, e
	}
	defer b.end(origin)
	if c.Operation != "connect" {
		p, e := b.permission(ctx, origin)
		if e != nil {
			return empty, e
		}
		if p == nil {
			return empty, &Error{4100, "Connect this website before changing chains"}
		}
		c.IdentityID = p.IdentityID
	}
	result, e := b.Backend.Control(ctx, c)
	if e != nil {
		return empty, controlError(e)
	}
	want, _ := json.Marshal(c)
	got, _ := json.Marshal(result.Control)
	p := result.Permission
	if string(want) != string(got) || p.Origin != origin || p.DeviceID != b.Backend.DeviceID() || p.ID == "" || c.IdentityID != "" && p.IdentityID != c.IdentityID || !approvedChain(&p, c.Chain.ChainID) {
		return empty, &Error{4100, "Permission response does not match this request"}
	}
	current, e := b.permission(ctx, origin)
	if e != nil || current == nil || current.ID != p.ID {
		return empty, &Error{4100, "Connected account is not present in the signed Vault catalogue"}
	}
	// Do not contact a dApp-provided RPC until its exact URL is approved.
	if c.Operation != "connect" {
		if e = checkChain(ctx, c.Chain); e != nil {
			return empty, e
		}
	}
	e = b.Store.update(func(s *state) error {
		if old, exists := s.Chains[c.Chain.ChainID]; exists {
			before, _ := json.Marshal(old)
			after, _ := json.Marshal(c.Chain)
			if string(before) != string(after) {
				return &Error{4100, "Chain definition changed while awaiting approval"}
			}
		}
		s.Chains[c.Chain.ChainID] = c.Chain
		site := s.Sites[origin]
		if c.Operation != "add" {
			site.ChainID = c.Chain.ChainID
		}
		site.RevokedID = ""
		site.LastUsed = time.Now().UTC()
		s.Sites[origin] = site
		return nil
	})
	return result, e
}
func (b *Bridge) sign(ctx context.Context, origin, method string, params []json.RawMessage, p vaultwire.WalletPermission, chain vaultwire.WalletChain) (any, error) {
	if e := b.begin(origin); e != nil {
		return nil, e
	}
	defer b.end(origin)
	b.signMu.Lock()
	defer b.signMu.Unlock()
	payload := walletsign.Payload{Origin: origin, IdentityID: p.IdentityID, Identity: p.Identity, Address: p.Address, ChainID: chain.ChainID, Method: method, Submit: method == "eth_sendTransaction"}
	if method == "eth_signTransaction" || method == "eth_sendTransaction" {
		if len(params) != 1 {
			return nil, &Error{-32602, "One transaction is required"}
		}
		id, _ := vaultwire.WalletChainID(chain.ChainID)
		normalized, e := foundry.PrepareTransaction(ctx, common.HexToAddress(p.Address), id, params[0], func(ctx context.Context, m string, args, out any) error {
			raw, e := rpc(ctx, chain, m, args)
			if e != nil {
				return e
			}
			return json.Unmarshal(raw, out)
		})
		if e != nil {
			return nil, &Error{-32602, "Invalid transaction or unavailable chain: " + e.Error()}
		}
		payload.Data = normalized
		payload.RPCURL = chain.RPCURLs[0]
	} else {
		if len(params) != 2 {
			return nil, &Error{-32602, "Signing requires address and data"}
		}
		dataIndex, addrIndex := 1, 0
		if method == "personal_sign" || method == "eth_signTypedData" || method == "eth_signTypedData_v1" {
			dataIndex, addrIndex = 0, 1
		}
		var address string
		if json.Unmarshal(params[addrIndex], &address) != nil || !strings.EqualFold(address, p.Address) {
			return nil, &Error{4100, "Signing address is not the connected identity"}
		}
		payload.Data = params[dataIndex]
		if strings.Contains(method, "TypedData") {
			var encoded string
			if json.Unmarshal(payload.Data, &encoded) == nil {
				payload.Data = json.RawMessage(encoded)
			}
		}
	}
	raw, _ := json.Marshal(payload)
	if _, e := walletsign.Decode(raw); e != nil {
		return nil, &Error{-32602, e.Error()}
	}
	sig, e := b.Backend.Sign(ctx, payload)
	if e != nil {
		return nil, controlError(e)
	}
	if e = walletsign.Verify(raw, sig, p.PublicKey); e != nil {
		return nil, &Error{-32603, "Signed payload failed verification"}
	}
	current, e := b.permission(ctx, origin)
	site, se := b.Store.site(origin)
	if e != nil || se != nil || current == nil || current.ID != p.ID || site.ChainID != chain.ChainID {
		return nil, &Error{4001, "Website permission or chain changed while signing"}
	}
	if e = b.Store.update(func(s *state) error {
		v := s.Sites[origin]
		v.LastUsed = time.Now().UTC()
		s.Sites[origin] = v
		return nil
	}); e != nil {
		return nil, &Error{-32603, "Could not persist wallet use"}
	}
	encoded := "0x" + hex.EncodeToString(sig)
	if !payload.Submit {
		return encoded, nil
	}
	if e = checkChain(ctx, chain); e != nil {
		return nil, e
	}
	response, e := rpc(ctx, chain, "eth_sendRawTransaction", []string{encoded})
	if e != nil {
		return nil, e
	}
	var hash string
	var tx types.Transaction
	if json.Unmarshal(response, &hash) != nil || tx.UnmarshalBinary(sig) != nil || !strings.EqualFold(hash, tx.Hash().Hex()) {
		return nil, &Error{-32603, "RPC returned a different transaction hash; submission status is uncertain"}
	}
	return hash, nil
}

// PublicIdentities is used only by native status/doctor, never eth_accounts.
func (b *Bridge) PublicIdentities(ctx context.Context) ([]identity.Record, error) {
	c, e := b.Backend.Catalog(ctx)
	if e != nil {
		return nil, e
	}
	out := []identity.Record{}
	for _, r := range c.Identities {
		if r.Type == "ethereum" {
			out = append(out, r)
		}
	}
	return out, nil
}
