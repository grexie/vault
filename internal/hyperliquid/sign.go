package hyperliquid

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Request struct {
	Network      string          `json:"network"`
	Signer       string          `json:"signer"`
	Action       json.RawMessage `json:"action"`
	Nonce        uint64          `json:"nonce"`
	VaultAddress *string         `json:"vaultAddress,omitempty"`
	ExpiresAfter *uint64         `json:"expiresAfter,omitempty"`
	action       object
	user         *userSchema
}
type Signature struct {
	R string `json:"r"`
	S string `json:"s"`
	V uint8  `json:"v"`
}
type ExchangeRequest struct {
	Action       json.RawMessage `json:"action"`
	Nonce        uint64          `json:"nonce"`
	Signature    Signature       `json:"signature"`
	VaultAddress *string         `json:"vaultAddress,omitempty"`
	ExpiresAfter *uint64         `json:"expiresAfter,omitempty"`
}

// Prepare constructs exactly the payload the human will approve. Network and
// signer are not mutable out-of-band options once this payload is submitted.
func Prepare(raw []byte, network, signer string) ([]byte, error) {
	m, e := parse(raw)
	if e != nil {
		return nil, e
	}
	if _, ok := m["network"]; ok {
		return nil, errors.New("network belongs in --network, not the exchange body")
	}
	if _, ok := m["signer"]; ok {
		return nil, errors.New("signer is selected by --identity")
	}
	m["network"] = network
	m["signer"] = signer
	a, ok := m["action"].(map[string]any)
	if !ok {
		return nil, errors.New("action object is required")
	}
	if _, ok := userRules[stringValue(a["type"])]; ok {
		chain := "Mainnet"
		if network == "testnet" {
			chain = "Testnet"
		}
		for k, v := range map[string]string{"signatureChainId": "0x66eee", "hyperliquidChain": chain} {
			if old, ok := a[k]; ok && old != v {
				return nil, errors.New("user action domain does not match the selected network")
			}
			a[k] = v
		}
		if a["type"] == "approveAgent" {
			if _, ok := a["agentName"]; !ok {
				a["agentName"] = ""
			}
		}
	}
	q, e := decodeMap(m)
	if e != nil {
		return nil, e
	}
	return json.Marshal(q)
}
func stringValue(v any) string { s, _ := v.(string); return s }
func Decode(raw []byte) (Request, error) {
	m, e := parse(raw)
	if e != nil {
		return Request{}, e
	}
	return decodeMap(m)
}
func decodeMap(m map[string]any) (Request, error) {
	q := Request{}
	v, e := fields(req("network", oneOf("mainnet", "testnet")), req("signer", address), req("action", func(v any) (any, error) { return v, nil }), req("nonce", unsigned), opt("vaultAddress", address), opt("expiresAfter", unsigned))(m)
	if e != nil {
		return q, e
	}
	o := v.(object)
	q.Network = o.str("network")
	q.Signer = common.HexToAddress(o.str("signer")).Hex()
	q.Nonce = o.get("nonce").(uint64)
	if v := o.get("vaultAddress"); v != nil {
		s := v.(string)
		q.VaultAddress = &s
	}
	if v := o.get("expiresAfter"); v != nil {
		n := v.(uint64)
		q.ExpiresAfter = &n
	}
	a, ok := o.get("action").(map[string]any)
	if !ok {
		return q, errors.New("action object is required")
	}
	kind := stringValue(a["type"])
	fs := []field{req("type", oneOf(kind))}
	if schema, ok := userRules[kind]; ok {
		q.user = &schema
		if q.VaultAddress != nil || q.ExpiresAfter != nil {
			return q, errors.New("user-signed actions cannot bind vaultAddress or expiresAfter; omit them")
		}
		chain := "Mainnet"
		if q.Network == "testnet" {
			chain = "Testnet"
		}
		fs = append(fs, req("signatureChainId", oneOf("0x66eee")), req("hyperliquidChain", oneOf(chain)))
		for _, f := range schema.fields {
			fs = append(fs, req(f.name, f.rule))
		}
	} else if schema, ok := l1Rules[kind]; ok {
		fs = append(fs, schema...)
	} else {
		return q, errors.New("unsupported Hyperliquid action")
	}
	v, e = fields(fs...)(a)
	if e != nil {
		return q, e
	}
	q.action = v.(object)
	if q.user != nil {
		n := q.action.get("nonce")
		if n == nil {
			n = q.action.get("time")
		}
		if n != q.Nonce {
			return q, errors.New("inner action nonce/time must equal the exchange nonce")
		}
		if u := q.action.str("user"); u != "" && !strings.EqualFold(u, q.Signer) {
			return q, errors.New("account settings must name the selected signer")
		}
	}
	q.Action, e = json.Marshal(q.action)
	return q, e
}

func uintWord(n uint64) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint64(b[24:], n)
	return b
}
func domain(name string, chain uint64) []byte {
	return crypto.Keccak256(crypto.Keccak256([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")), crypto.Keccak256([]byte(name)), crypto.Keccak256([]byte("1")), uintWord(chain), make([]byte, 32))
}
func (q Request) ActionHash() []byte {
	if q.user != nil {
		return nil
	}
	b := pack(nil, q.action)
	n := make([]byte, 8)
	binary.BigEndian.PutUint64(n, q.Nonce)
	b = append(b, n...)
	if q.VaultAddress == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = append(b, common.HexToAddress(*q.VaultAddress).Bytes()...)
	}
	if q.ExpiresAfter != nil {
		b = append(b, 0)
		binary.BigEndian.PutUint64(n, *q.ExpiresAfter)
		b = append(b, n...)
	}
	return crypto.Keccak256(b)
}
func (q Request) Digest() []byte {
	if q.user == nil {
		source := "a"
		if q.Network == "testnet" {
			source = "b"
		}
		body := crypto.Keccak256(crypto.Keccak256([]byte("Agent(string source,bytes32 connectionId)")), crypto.Keccak256([]byte(source)), q.ActionHash())
		return crypto.Keccak256([]byte{0x19, 0x01}, domain("Exchange", 1337), body)
	}
	typ := "HyperliquidTransaction:" + q.user.name + "(string hyperliquidChain"
	for _, f := range q.user.fields {
		typ += "," + f.typ + " " + f.name
	}
	typ += ")"
	b := append(crypto.Keccak256([]byte(typ)), crypto.Keccak256([]byte(q.action.str("hyperliquidChain")))...)
	for _, f := range q.user.fields {
		v := q.action.get(f.name)
		var w []byte
		switch f.typ {
		case "string":
			w = crypto.Keccak256([]byte(v.(string)))
		case "address":
			w = common.LeftPadBytes(common.HexToAddress(v.(string)).Bytes(), 32)
		case "uint64":
			w = uintWord(v.(uint64))
		case "bool":
			n := uint64(0)
			if v.(bool) {
				n = 1
			}
			w = uintWord(n)
		default:
			panic("unknown internal typed field")
		}
		b = append(b, w...)
	}
	return crypto.Keccak256([]byte{0x19, 0x01}, domain("HyperliquidSignTransaction", 421614), crypto.Keccak256(b))
}

func PublicAddress(publicKey string) (string, error) {
	b, e := hex.DecodeString(strings.TrimPrefix(publicKey, "0x"))
	if e != nil {
		return "", errors.New("invalid Ethereum public key")
	}
	k, e := crypto.UnmarshalPubkey(b)
	if e != nil {
		return "", errors.New("invalid Ethereum public key")
	}
	return crypto.PubkeyToAddress(*k).Hex(), nil
}
func CheckBinding(raw []byte, network, publicKey string) error {
	q, e := Decode(raw)
	if e != nil {
		return e
	}
	a, e := PublicAddress(publicKey)
	if e != nil {
		return e
	}
	if q.Network != network || !strings.EqualFold(q.Signer, a) {
		return errors.New("Hyperliquid network or signer differs from the approved identity")
	}
	return nil
}
func Sign(key *ecdsa.PrivateKey, raw []byte) ([]byte, error) {
	q, e := Decode(raw)
	if e != nil {
		return nil, e
	}
	if !strings.EqualFold(crypto.PubkeyToAddress(key.PublicKey).Hex(), q.Signer) {
		return nil, errors.New("key does not match the reviewed Hyperliquid signer")
	}
	s, e := crypto.Sign(q.Digest(), key)
	if e != nil {
		return nil, e
	}
	return json.Marshal(ExchangeRequest{Action: q.Action, Nonce: q.Nonce, Signature: Signature{"0x" + hex.EncodeToString(s[:32]), "0x" + hex.EncodeToString(s[32:64]), s[64] + 27}, VaultAddress: q.VaultAddress, ExpiresAfter: q.ExpiresAfter})
}

// Verify rejects any substituted envelope and recovers the signer against the
// owner's signed authorization, not only the caller's claimed address.
var scalarPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{1,64}$`)

func Verify(raw, signed []byte, ownerPublicKey string) error {
	q, e := Decode(raw)
	if e != nil {
		return e
	}
	m, e := parse(signed)
	if e != nil {
		return e
	}
	sv, e := fields(req("r", text), req("s", text), req("v", bounded(27, 28)))(m["signature"])
	if e != nil {
		return e
	}
	sig := sv.(object)
	delete(m, "signature")
	body, e := json.Marshal(m)
	if e != nil {
		return e
	}
	prepared, e := Prepare(body, q.Network, q.Signer)
	if e != nil {
		return e
	}
	expected, _ := json.Marshal(q)
	if !bytes.Equal(prepared, expected) {
		return errors.New("signed exchange body differs from the approved request")
	}
	a, e := PublicAddress(ownerPublicKey)
	if e != nil || !strings.EqualFold(a, q.Signer) {
		return errors.New("authorized public key differs from the requested signer")
	}
	b := make([]byte, 65)
	for i, name := range []string{"r", "s"} {
		s := sig.str(name)
		if !scalarPattern.MatchString(s) {
			return errors.New("invalid signature scalar")
		}
		n, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return errors.New("invalid signature scalar")
		}
		n.FillBytes(b[i*32 : (i+1)*32])
	}
	b[64] = byte(sig.get("v").(uint64) - 27)
	if !crypto.ValidateSignatureValues(b[64], new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:64]), true) {
		return errors.New("noncanonical Hyperliquid signature")
	}
	pub, e := crypto.SigToPub(q.Digest(), b)
	if e != nil || !strings.EqualFold(crypto.PubkeyToAddress(*pub).Hex(), a) {
		return errors.New("Hyperliquid signature verification failed")
	}
	return nil
}
