package vaultwire

import (
	"errors"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"
)

type WalletCurrency struct {
	Name     string `json:"name"`
	Symbol   string `json:"symbol"`
	Decimals int    `json:"decimals"`
}
type WalletChain struct {
	ChainID      string         `json:"chainId"`
	Name         string         `json:"chainName"`
	Currency     WalletCurrency `json:"nativeCurrency"`
	RPCURLs      []string       `json:"rpcUrls"`
	ExplorerURLs []string       `json:"blockExplorerUrls,omitempty"`
}
type WalletPermission struct {
	ID         string    `json:"id"`
	DeviceID   string    `json:"deviceId"`
	Origin     string    `json:"origin"`
	IdentityID string    `json:"identityId"`
	Identity   string    `json:"identity"`
	Address    string    `json:"address"`
	PublicKey  string    `json:"publicKey"`
	Chains     []string  `json:"chains"`
	CreatedAt  time.Time `json:"createdAt"`
	LastUsedAt time.Time `json:"lastUsedAt"`
}
type WalletControl struct {
	Origin     string      `json:"origin"`
	Operation  string      `json:"operation"`
	IdentityID string      `json:"identityId,omitempty"`
	Chain      WalletChain `json:"chain"`
}
type WalletControlResult struct {
	Permission WalletPermission `json:"permission"`
	Control    WalletControl    `json:"control"`
}

func WalletOrigin(origin string) error {
	u, e := url.Parse(origin)
	if e != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.String() != origin || strings.ToLower(u.Host) != u.Host || len(origin) > 512 {
		return errors.New("invalid website origin")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return errors.New("wallet websites require HTTPS or local development")
	}
	return nil
}
func WalletChainID(s string) (*big.Int, error) {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 || len(s) > 66 {
		return nil, errors.New("chain ID must be hexadecimal")
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	if !ok || n.Sign() <= 0 || "0x"+n.Text(16) != s {
		return nil, errors.New("chain ID must be a canonical positive hex quantity")
	}
	return n, nil
}
func WalletURL(s string, local bool) error {
	u, e := url.Parse(s)
	if e != nil || len(s) > 2048 || u.Host == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("invalid RPC or explorer URL")
	}
	ip := net.ParseIP(u.Hostname())
	loop := ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(local && u.Scheme == "http" && loop) {
		return errors.New("URLs require HTTPS; local RPC must use a literal loopback address")
	}
	if ip != nil && !ip.IsGlobalUnicast() && !loop {
		return errors.New("nonpublic RPC address")
	}
	if ip != nil && (ip.IsPrivate() || loop) && !(local && loop) {
		return errors.New("private RPC address is not allowed")
	}
	if u.Hostname() == "localhost" {
		return errors.New("use a literal loopback IP for local RPC")
	}
	return nil
}
func (c WalletChain) Validate() error {
	if _, e := WalletChainID(c.ChainID); e != nil {
		return e
	}
	if len(c.Name) < 1 || len(c.Name) > 100 || len(c.Currency.Name) < 1 || len(c.Currency.Name) > 100 || len(c.Currency.Symbol) < 1 || len(c.Currency.Symbol) > 20 || c.Currency.Decimals < 0 || c.Currency.Decimals > 255 || len(c.RPCURLs) < 1 || len(c.RPCURLs) > 5 || len(c.ExplorerURLs) > 5 {
		return errors.New("invalid chain metadata")
	}
	for _, u := range c.RPCURLs {
		if e := WalletURL(u, true); e != nil {
			return e
		}
	}
	for _, u := range c.ExplorerURLs {
		if e := WalletURL(u, false); e != nil {
			return e
		}
	}
	return nil
}
func (c WalletControl) Validate() error {
	if e := WalletOrigin(c.Origin); e != nil {
		return e
	}
	if c.Operation != "connect" && c.Operation != "switch" && c.Operation != "add" {
		return errors.New("unknown wallet permission operation")
	}
	return c.Chain.Validate()
}
