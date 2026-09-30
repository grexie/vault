// Package foundry adapts vanilla Foundry JSON-RPC to a sign-only Vault device.
// It runs exclusively on the caller's machine, never in the hosted relay.
package foundry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/grexie/vault/internal/identity"
)

type Signer interface {
	SignEthereum(context.Context, []byte) ([]byte, error)
}

type Config struct {
	Upstream string
	Address  common.Address
	ChainID  *big.Int
	// Broadcast permits the caller-side adapter to submit signed bytes only in
	// response to eth_sendTransaction or eth_sendRawTransaction. Signing itself
	// remains separate and cannot broadcast.
	Broadcast bool
}

type Adapter struct {
	cfg      Config
	signer   Signer
	client   *http.Client
	url      string
	host     string
	token    string
	server   *http.Server
	listener net.Listener
	sendMu   sync.Mutex
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func New(ctx context.Context, cfg Config, signer Signer) (*Adapter, error) {
	u, err := url.Parse(cfg.Upstream)
	if err != nil || u.Host == "" || u.Fragment != "" || (u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname()))) {
		return nil, errors.New("upstream must be HTTPS or a loopback test node")
	}
	if signer == nil || cfg.Address == (common.Address{}) || cfg.ChainID == nil || cfg.ChainID.Sign() <= 0 {
		return nil, errors.New("identity and explicit chain ID are required")
	}
	a := &Adapter{cfg: cfg, signer: signer, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("upstream redirects are disabled") }}}
	a.cfg.ChainID = new(big.Int).Set(cfg.ChainID)
	if err = a.checkChain(ctx); err != nil {
		return nil, err
	}
	return a, nil
}
func isLoopback(host string) bool { ip := net.ParseIP(host); return ip != nil && ip.IsLoopback() }

// Start always binds a random IPv4 loopback port and a secret per-process path.
// There is no network-wide bind option and browser origins are rejected.
func (a *Adapter) Start() (string, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		l.Close()
		return "", err
	}
	a.token = base64.RawURLEncoding.EncodeToString(b)
	a.host = l.Addr().String()
	a.listener = l
	a.url = "http://" + a.host + "/" + a.token
	a.server = &http.Server{Handler: a, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	go a.server.Serve(l)
	return a.url, nil
}
func (a *Adapter) Close() error {
	if a.server != nil {
		return a.server.Close()
	}
	return nil
}

func (a *Adapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if a.token == "" || r.Host != a.host || r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" || subtle.ConstantTimeCompare([]byte(r.URL.Path), []byte("/"+a.token)) != 1 {
		http.Error(w, "local RPC access denied", http.StatusForbidden)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2*1024*1024))
	if err != nil {
		http.Error(w, "request too large", 413)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(bytes.TrimSpace(b)) > 0 && bytes.TrimSpace(b)[0] == '[' {
		var qs []request
		if json.Unmarshal(b, &qs) != nil || len(qs) == 0 || len(qs) > 100 {
			json.NewEncoder(w).Encode(fail(nil, -32600, "invalid batch"))
			return
		}
		rs := []response{}
		for _, q := range qs {
			if len(q.ID) == 0 {
				continue
			}
			rs = append(rs, a.handle(r.Context(), q))
		}
		if len(rs) == 0 {
			w.WriteHeader(204)
			return
		}
		json.NewEncoder(w).Encode(rs)
		return
	}
	var q request
	if json.Unmarshal(b, &q) != nil {
		json.NewEncoder(w).Encode(fail(nil, -32700, "invalid JSON"))
		return
	}
	// Financial methods without an ID are never executed: there is no way to
	// return an approval failure or a receipt to the caller.
	if len(q.ID) == 0 {
		w.WriteHeader(204)
		return
	}
	json.NewEncoder(w).Encode(a.handle(r.Context(), q))
}
func fail(id json.RawMessage, code int, message string) response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{code, message}}
}
func result(id json.RawMessage, v any) response {
	b, _ := json.Marshal(v)
	return response{JSONRPC: "2.0", ID: id, Result: b}
}

func (a *Adapter) handle(ctx context.Context, q request) response {
	if q.JSONRPC != "2.0" || len(q.Method) > 100 {
		return fail(q.ID, -32600, "invalid JSON-RPC request")
	}
	switch q.Method {
	case "eth_accounts":
		return result(q.ID, []common.Address{a.cfg.Address})
	case "eth_coinbase":
		return result(q.ID, a.cfg.Address)
	case "eth_signTransaction", "eth_sendTransaction":
		if q.Method == "eth_sendTransaction" && !a.cfg.Broadcast {
			return fail(q.ID, -32601, "broadcast disabled; use eth_signTransaction and publish with your own caller")
		}
		a.sendMu.Lock()
		defer a.sendMu.Unlock()
		var params []json.RawMessage
		if json.Unmarshal(q.Params, &params) != nil || len(params) != 1 {
			return fail(q.ID, -32602, "one transaction is required")
		}
		tx, err := a.prepare(ctx, params[0])
		if err != nil {
			return fail(q.ID, -32602, err.Error())
		}
		raw, err := a.signer.SignEthereum(ctx, tx)
		if err != nil {
			return fail(q.ID, 4001, "Vault signing was denied or unavailable")
		}
		if _, err = identity.VerifyEthereum(tx, raw); err != nil {
			return fail(q.ID, -32000, err.Error())
		}
		if q.Method == "eth_signTransaction" {
			return result(q.ID, hexutil.Bytes(raw))
		}
		if err = a.checkChain(ctx); err != nil {
			return fail(q.ID, -32000, err.Error())
		}
		return a.forward(ctx, q.ID, "eth_sendRawTransaction", []any{hexutil.Bytes(raw)})
	case "eth_sendRawTransaction":
		if !a.cfg.Broadcast {
			return fail(q.ID, -32601, "broadcast disabled")
		}
		var params []hexutil.Bytes
		if json.Unmarshal(q.Params, &params) != nil || len(params) != 1 {
			return fail(q.ID, -32602, "one signed transaction is required")
		}
		var tx types.Transaction
		if tx.UnmarshalBinary(params[0]) != nil || !tx.Protected() || tx.ChainId().Cmp(a.cfg.ChainID) != 0 {
			return fail(q.ID, -32602, "signed transaction chain mismatch")
		}
		from, err := types.Sender(types.LatestSignerForChainID(a.cfg.ChainID), &tx)
		if err != nil || from != a.cfg.Address {
			return fail(q.ID, -32602, "signed transaction identity mismatch")
		}
		if err = a.checkChain(ctx); err != nil {
			return fail(q.ID, -32000, err.Error())
		}
		return a.forward(ctx, q.ID, q.Method, params)
	default:
		if !readMethods[q.Method] {
			return fail(q.ID, -32601, "unsupported method")
		}
		var params any
		if len(q.Params) > 0 && json.Unmarshal(q.Params, &params) != nil {
			return fail(q.ID, -32602, "invalid params")
		}
		return a.forward(ctx, q.ID, q.Method, params)
	}
}

// No prefix allowlist: admin, wallet, personal, debug mutations, account unlock,
// raw-digest signing, and upstream eth_sendTransaction can never pass through.
var readMethods = map[string]bool{
	"eth_chainId": true, "net_version": true, "web3_clientVersion": true, "eth_blockNumber": true,
	"eth_getBalance": true, "eth_getTransactionCount": true, "eth_getCode": true, "eth_getStorageAt": true,
	"eth_call": true, "eth_estimateGas": true, "eth_gasPrice": true, "eth_maxPriorityFeePerGas": true,
	"eth_feeHistory": true, "eth_getBlockByNumber": true, "eth_getBlockByHash": true,
	"eth_getTransactionByHash": true, "eth_getTransactionReceipt": true, "eth_getLogs": true,
	"eth_createAccessList": true, "eth_getProof": true, "eth_getBlockTransactionCountByNumber": true,
	"eth_getBlockTransactionCountByHash": true, "eth_getTransactionByBlockHashAndIndex": true,
	"eth_getTransactionByBlockNumberAndIndex": true, "eth_getUncleCountByBlockHash": true,
	"eth_getUncleCountByBlockNumber": true, "eth_syncing": true,
}

func (a *Adapter) call(ctx context.Context, method string, params any, out any) error {
	r := a.forward(ctx, json.RawMessage("1"), method, params)
	if r.Error != nil {
		return fmt.Errorf("upstream %s failed", method)
	}
	if json.Unmarshal(r.Result, out) != nil {
		return errors.New("invalid upstream response")
	}
	return nil
}
func (a *Adapter) forward(ctx context.Context, id json.RawMessage, method string, params any) response {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	req, err := http.NewRequestWithContext(ctx, "POST", a.cfg.Upstream, bytes.NewReader(b))
	if err != nil {
		return fail(id, -32000, "invalid upstream")
	}
	req.Header.Set("Content-Type", "application/json")
	r, err := a.client.Do(req)
	if err != nil {
		return fail(id, -32000, "upstream unavailable")
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8*1024*1024+1))
	if err != nil || len(raw) > 8*1024*1024 || r.StatusCode != 200 {
		return fail(id, -32000, "upstream request failed")
	}
	var res response
	if json.Unmarshal(raw, &res) != nil || res.JSONRPC != "2.0" || string(res.ID) != "1" || (res.Error == nil && len(res.Result) == 0) {
		return fail(id, -32000, "invalid upstream response")
	}
	res.ID = id
	// Don't forward upstream error text: it can contain RPC URL credentials.
	if res.Error != nil {
		res.Error.Message = "upstream rejected " + method
	}
	return res
}
func (a *Adapter) checkChain(ctx context.Context) error {
	var chain hexutil.Big
	if err := a.call(ctx, "eth_chainId", []any{}, &chain); err != nil {
		return err
	}
	if (*big.Int)(&chain).Cmp(a.cfg.ChainID) != 0 {
		return errors.New("upstream chain does not match the explicitly selected chain")
	}
	return nil
}
func (a *Adapter) prepare(ctx context.Context, raw []byte) ([]byte, error) {
	tx, err := identity.DecodeEthereum(raw)
	if err != nil {
		return nil, err
	}
	if tx.From != a.cfg.Address {
		return nil, errors.New("transaction sender does not match the selected identity")
	}
	if tx.Type != nil && *tx.Type > 2 {
		return nil, errors.New("unsupported transaction type")
	}
	if err = a.checkChain(ctx); err != nil {
		return nil, err
	}
	if tx.ChainID != nil && (*big.Int)(tx.ChainID).Cmp(a.cfg.ChainID) != 0 {
		return nil, errors.New("transaction chain mismatch")
	}
	tx.ChainID = (*hexutil.Big)(new(big.Int).Set(a.cfg.ChainID))
	if tx.Nonce == nil {
		var n hexutil.Uint64
		if err = a.call(ctx, "eth_getTransactionCount", []any{tx.From, "pending"}, &n); err != nil {
			return nil, err
		}
		tx.Nonce = &n
	}
	if tx.GasPrice == nil && tx.MaxFeePerGas == nil && tx.MaxPriorityFeePerGas == nil {
		if tx.Type != nil && *tx.Type < 2 {
			var p hexutil.Big
			if err = a.call(ctx, "eth_gasPrice", []any{}, &p); err != nil {
				return nil, err
			}
			tx.GasPrice = &p
		} else {
			var block struct {
				BaseFee *hexutil.Big `json:"baseFeePerGas"`
			}
			if err = a.call(ctx, "eth_getBlockByNumber", []any{"latest", false}, &block); err != nil {
				return nil, err
			}
			if block.BaseFee == nil {
				var p hexutil.Big
				if err = a.call(ctx, "eth_gasPrice", []any{}, &p); err != nil {
					return nil, err
				}
				tx.GasPrice = &p
			} else {
				var tip hexutil.Big
				if err = a.call(ctx, "eth_maxPriorityFeePerGas", []any{}, &tip); err != nil {
					return nil, err
				}
				fee := new(big.Int).Mul((*big.Int)(block.BaseFee), big.NewInt(2))
				fee.Add(fee, (*big.Int)(&tip))
				tx.MaxFeePerGas = (*hexutil.Big)(fee)
				tx.MaxPriorityFeePerGas = &tip
			}
		}
	}
	if tx.Gas == nil {
		var gas hexutil.Uint64
		if err = a.call(ctx, "eth_estimateGas", []any{tx}, &gas); err != nil {
			return nil, err
		}
		tx.Gas = &gas
	}
	if _, err = tx.Transaction(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(tx)
	return b, err
}

// HideLocalURL strips the per-process capability from errors and summaries.
func HideLocalURL(s string) string {
	if i := strings.Index(s, "/"); i >= 0 {
		return s[:i]
	}
	return s
}
