// Package identity contains device-side key operations. It must not be imported
// by the hosted cloud service: private keys belong to the user's device agent.
package identity

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// EthereumTransaction uses the standard Ethereum JSON-RPC transaction shape.
// All quantities are hex strings. No fee, nonce, chain, or destination is chosen
// inside the key-holding device; callers resolve these before asking approval.
type EthereumTransaction struct {
	From                 common.Address    `json:"from"`
	To                   *common.Address   `json:"to,omitempty"`
	Type                 *hexutil.Uint64   `json:"type,omitempty"`
	ChainID              *hexutil.Big      `json:"chainId"`
	Nonce                *hexutil.Uint64   `json:"nonce"`
	Gas                  *hexutil.Uint64   `json:"gas"`
	GasPrice             *hexutil.Big      `json:"gasPrice,omitempty"`
	MaxFeePerGas         *hexutil.Big      `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *hexutil.Big      `json:"maxPriorityFeePerGas,omitempty"`
	Value                *hexutil.Big      `json:"value,omitempty"`
	Data                 *hexutil.Bytes    `json:"data,omitempty"`
	Input                *hexutil.Bytes    `json:"input,omitempty"`
	AccessList           *types.AccessList `json:"accessList,omitempty"`
}

func DecodeEthereum(raw []byte) (EthereumTransaction, error) {
	var a EthereumTransaction
	// JSON member names are case-sensitive in the browser. Go's struct decoder
	// accepts case variants; reject them and duplicates before either review path.
	allowed := map[string]bool{}
	for _, name := range []string{"from", "to", "type", "chainId", "nonce", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "value", "data", "input", "accessList"} {
		allowed[name] = true
	}
	scan := json.NewDecoder(bytes.NewReader(raw))
	first, e := scan.Token()
	if e != nil || first != json.Delim('{') {
		return a, errors.New("transaction must be a JSON object")
	}
	seen := map[string]bool{}
	for scan.More() {
		token, e := scan.Token()
		name, ok := token.(string)
		if e != nil || !ok || !allowed[name] || seen[name] {
			return a, errors.New("duplicate or noncanonical transaction field")
		}
		seen[name] = true
		var value json.RawMessage
		if scan.Decode(&value) != nil {
			return a, errors.New("invalid transaction value")
		}
	}
	if _, e = scan.Token(); e != nil {
		return a, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 1024*1024 {
		return a, errors.New("transaction exceeds size limit")
	}
	if e := d.Decode(&a); e != nil {
		return a, errors.New("invalid or unsupported Ethereum transaction fields")
	}
	if d.Decode(new(any)) != io.EOF {
		return a, errors.New("trailing transaction data")
	}
	return a, nil
}

func (a EthereumTransaction) Transaction() (*types.Transaction, error) {
	if a.ChainID == nil || (*big.Int)(a.ChainID).Sign() <= 0 || (*big.Int)(a.ChainID).BitLen() > 256 {
		return nil, errors.New("a positive explicit chainId is required")
	}
	if a.From == (common.Address{}) || a.Nonce == nil || a.Gas == nil || *a.Gas == 0 {
		return nil, errors.New("from, nonce and nonzero gas are required")
	}
	for _, n := range []*hexutil.Big{a.Value, a.GasPrice, a.MaxFeePerGas, a.MaxPriorityFeePerGas} {
		if n != nil && ((*big.Int)(n).Sign() < 0 || (*big.Int)(n).BitLen() > 256) {
			return nil, errors.New("invalid transaction quantity")
		}
	}
	if a.Data != nil && a.Input != nil && !bytes.Equal(*a.Data, *a.Input) {
		return nil, errors.New("data and input disagree")
	}
	var data []byte
	if a.Data != nil {
		data = *a.Data
	}
	if a.Input != nil {
		data = *a.Input
	}
	if len(data) > 128*1024 {
		return nil, errors.New("transaction calldata exceeds limit")
	}
	value := new(big.Int)
	if a.Value != nil {
		value.Set((*big.Int)(a.Value))
	}
	var access types.AccessList
	if a.AccessList != nil {
		access = *a.AccessList
	}
	typ := uint64(0)
	if a.AccessList != nil {
		typ = 1
	}
	if a.MaxFeePerGas != nil || a.MaxPriorityFeePerGas != nil {
		typ = 2
	}
	if a.Type != nil {
		typ = uint64(*a.Type)
	}
	if typ > 2 {
		return nil, errors.New("only replay-protected legacy, EIP-2930 and EIP-1559 transactions are supported")
	}
	if typ < 2 {
		if a.GasPrice == nil || a.MaxFeePerGas != nil || a.MaxPriorityFeePerGas != nil {
			return nil, errors.New("legacy and EIP-2930 require gasPrice and no dynamic fees")
		}
		if typ == 0 && len(access) > 0 {
			return nil, errors.New("legacy transactions cannot have an access list")
		}
		if typ == 0 {
			return types.NewTx(&types.LegacyTx{Nonce: uint64(*a.Nonce), GasPrice: (*big.Int)(a.GasPrice), Gas: uint64(*a.Gas), To: a.To, Value: value, Data: data}), nil
		}
		return types.NewTx(&types.AccessListTx{ChainID: (*big.Int)(a.ChainID), Nonce: uint64(*a.Nonce), GasPrice: (*big.Int)(a.GasPrice), Gas: uint64(*a.Gas), To: a.To, Value: value, Data: data, AccessList: access}), nil
	}
	if a.GasPrice != nil || a.MaxFeePerGas == nil || a.MaxPriorityFeePerGas == nil || (*big.Int)(a.MaxFeePerGas).Cmp((*big.Int)(a.MaxPriorityFeePerGas)) < 0 {
		return nil, errors.New("EIP-1559 requires maxFeePerGas >= maxPriorityFeePerGas and no gasPrice")
	}
	return types.NewTx(&types.DynamicFeeTx{ChainID: (*big.Int)(a.ChainID), Nonce: uint64(*a.Nonce), GasFeeCap: (*big.Int)(a.MaxFeePerGas), GasTipCap: (*big.Int)(a.MaxPriorityFeePerGas), Gas: uint64(*a.Gas), To: a.To, Value: value, Data: data, AccessList: access}), nil
}

func EthereumKey(raw []byte) (*ecdsa.PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	if err != nil || len(b) != 32 {
		clear(b)
		return nil, errors.New("Ethereum private key must be 32 bytes of hex")
	}
	defer clear(b)
	return crypto.ToECDSA(b)
}

// SignEthereum returns signed bytes. There is deliberately no network client or
// broadcast operation in this package.
func SignEthereum(key *ecdsa.PrivateKey, raw []byte) ([]byte, error) {
	a, err := DecodeEthereum(raw)
	if err != nil {
		return nil, err
	}
	if crypto.PubkeyToAddress(key.PublicKey) != a.From {
		return nil, errors.New("transaction sender does not match the selected identity")
	}
	tx, err := a.Transaction()
	if err != nil {
		return nil, err
	}
	signed, err := types.SignTx(tx, types.LatestSignerForChainID((*big.Int)(a.ChainID)), key)
	if err != nil {
		return nil, err
	}
	return signed.MarshalBinary()
}

// VerifyEthereum protects the caller from a substituted relay response. It checks
// the signer and every transaction field by comparing the unsigned signing hash.
func VerifyEthereum(rawRequest, signed []byte) (*types.Transaction, error) {
	a, err := DecodeEthereum(rawRequest)
	if err != nil {
		return nil, err
	}
	want, err := a.Transaction()
	if err != nil {
		return nil, err
	}
	var got types.Transaction
	if err = got.UnmarshalBinary(signed); err != nil {
		return nil, errors.New("invalid signed transaction")
	}
	signer := types.LatestSignerForChainID((*big.Int)(a.ChainID))
	from, err := types.Sender(signer, &got)
	if err != nil || from != a.From || !got.Protected() || got.ChainId().Cmp((*big.Int)(a.ChainID)) != 0 || got.Type() != want.Type() || signer.Hash(&got) != signer.Hash(want) {
		return nil, errors.New("signed transaction differs from the approved transaction")
	}
	return &got, nil
}

func ethereumDigest(a EthereumTransaction, tx *types.Transaction) string {
	return types.LatestSignerForChainID((*big.Int)(a.ChainID)).Hash(tx).Hex()
}
