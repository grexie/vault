//go:build unix

package browserwallet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/grexie/vault/internal/vaultwire"
)

var readMethods = map[string]bool{"web3_clientVersion": true, "web3_sha3": true, "eth_blockNumber": true, "eth_getBalance": true, "eth_getTransactionCount": true, "eth_getCode": true, "eth_getStorageAt": true, "eth_call": true, "eth_estimateGas": true, "eth_gasPrice": true, "eth_maxPriorityFeePerGas": true, "eth_feeHistory": true, "eth_getBlockByNumber": true, "eth_getBlockByHash": true, "eth_getTransactionByHash": true, "eth_getTransactionReceipt": true, "eth_getLogs": true, "eth_createAccessList": true, "eth_getProof": true, "eth_getBlockTransactionCountByNumber": true, "eth_getBlockTransactionCountByHash": true, "eth_getTransactionByBlockHashAndIndex": true, "eth_getTransactionByBlockNumberAndIndex": true, "eth_getUncleCountByBlockHash": true, "eth_getUncleCountByBlockNumber": true, "eth_getUncleByBlockHashAndIndex": true, "eth_getUncleByBlockNumberAndIndex": true, "eth_syncing": true, "eth_getBlockReceipts": true}

// Special-use networks include tailnet/CGNAT, not just RFC1918 addresses.
var prohibitedRPC = func() []netip.Prefix {
	out := []netip.Prefix{}
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "fc00::/7", "fe80::/10"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func publicRPCIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() {
		return false
	}
	for _, p := range prohibitedRPC {
		if p.Contains(a) {
			return false
		}
	}
	return !a.Is6() || netip.MustParsePrefix("2000::/3").Contains(a)
}

func rpcClient(endpoint string) *http.Client {
	u, _ := url.Parse(endpoint)
	local := net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()
	transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 15 * time.Second, TLSHandshakeTimeout: 10 * time.Second, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, errors.New("RPC host unavailable")
		}
		for _, entry := range ips {
			ip := entry.IP
			if local && ip.IsLoopback() || !local && publicRPCIP(ip) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
		}
		return nil, errors.New("RPC resolved to a prohibited address")
	}}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("RPC redirects are refused") }}
}
func rpc(ctx context.Context, chain vaultwire.WalletChain, method string, params any) (json.RawMessage, error) {
	if e := chain.Validate(); e != nil {
		return nil, e
	}
	b, e := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if e != nil || len(b) > 192*1024 {
		return nil, &Error{-32602, "RPC request exceeds size limit"}
	}
	// Use only the explicitly approved endpoint. Failover requires the same
	// chain metadata approval; never follow redirects or arbitrary method URLs.
	endpoint := chain.RPCURLs[0]
	client := rpcClient(endpoint)
	defer client.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e != nil {
		return nil, &Error{4901, "Chain RPC unavailable"}
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
	if e != nil || len(raw) > 4*1024*1024 || res.StatusCode != 200 {
		return nil, &Error{-32000, "Chain RPC returned an invalid response"}
	}
	var result struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *Error          `json:"error"`
	}
	if json.Unmarshal(raw, &result) != nil || result.JSONRPC != "2.0" || string(result.ID) != "1" {
		return nil, &Error{-32603, "Invalid chain RPC response"}
	}
	if result.Error != nil {
		return nil, &Error{result.Error.Code, "Chain RPC rejected " + method}
	}
	if len(result.Result) == 0 {
		return nil, &Error{-32603, "Missing chain RPC result"}
	}
	return result.Result, nil
}
func checkChain(ctx context.Context, c vaultwire.WalletChain) error {
	raw, e := rpc(ctx, c, "eth_chainId", []any{})
	if e != nil {
		return e
	}
	var id string
	if json.Unmarshal(raw, &id) != nil || id != c.ChainID {
		return &Error{4901, "RPC chain differs from approved chain"}
	}
	return nil
}
