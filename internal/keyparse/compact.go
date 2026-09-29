package keyparse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"math/big"

	"golang.org/x/crypto/ssh"
)

// compactKey stores standard private parameters without redundant public and
// precomputed values. RSA's factors and public exponent determine the key; a
// 4096-bit RSA key fits comfortably in a 2 KiB authenticator largeBlob. This is
// private serialization, not encryption: callers MUST encrypt it using PRF.
type compactKey struct {
	Version  int      `json:"v"`
	Type     string   `json:"t"`
	Exponent int      `json:"e,omitempty"`
	Primes   [][]byte `json:"p,omitempty"`
	Secret   []byte   `json:"d,omitempty"`
	Curve    string   `json:"c,omitempty"`
}

func Compact(data, password []byte) (string, error) {
	k, e := parseRaw(data, password)
	if e != nil {
		return "", e
	}
	v := compactKey{Version: 1}
	switch key := k.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() > 8192 {
			return "", errors.New("RSA keys larger than 8192 bits exceed the portable keychain limit")
		}
		v.Type = "rsa"
		v.Exponent = key.E
		for _, p := range key.Primes {
			v.Primes = append(v.Primes, p.Bytes())
		}
	case *ecdsa.PrivateKey:
		v.Type = "ecdsa"
		v.Curve = key.Curve.Params().Name
		v.Secret = key.D.Bytes()
	case *ed25519.PrivateKey:
		v.Type = "ed25519"
		v.Secret = key.Seed()
	case ed25519.PrivateKey:
		v.Type = "ed25519"
		v.Secret = key.Seed()
	default:
		return "", errors.New("unsupported key algorithm; use RSA, Ed25519 or ECDSA")
	}
	b, e := json.Marshal(v)
	return string(b), e
}

func parseCompact(data []byte) (ssh.Signer, error) {
	if len(data) > 1800 {
		return nil, errors.New("compact key is too large")
	}
	var v compactKey
	if e := json.Unmarshal(data, &v); e != nil {
		return nil, e
	}
	if v.Version != 1 {
		return nil, errors.New("unsupported compact key version")
	}
	switch v.Type {
	case "rsa":
		if v.Exponent < 3 || v.Exponent%2 == 0 || v.Exponent > 1<<31-1 || len(v.Primes) < 2 || len(v.Primes) > 4 {
			return nil, errors.New("invalid RSA parameters")
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: big.NewInt(1), E: v.Exponent}}
		// phi = product(p_i - 1). Inverting e modulo phi produces a valid
		// private exponent. Go's RSA validation and precomputation then validate
		// and derive the redundant values before any signature is permitted.
		phi := big.NewInt(1)
		for _, b := range v.Primes {
			if len(b) < 64 || len(b) > 1024 {
				return nil, errors.New("invalid RSA prime size")
			}
			p := new(big.Int).SetBytes(b)
			key.Primes = append(key.Primes, p)
			key.N.Mul(key.N, p)
			phi.Mul(phi, new(big.Int).Sub(p, big.NewInt(1)))
		}
		if key.N.BitLen() > 8192 {
			return nil, errors.New("RSA modulus too large")
		}
		key.D = new(big.Int).ModInverse(big.NewInt(int64(v.Exponent)), phi)
		if key.D == nil {
			return nil, errors.New("invalid RSA exponent")
		}
		if e := key.Validate(); e != nil {
			return nil, e
		}
		key.Precompute()
		return ssh.NewSignerFromKey(key)
	case "ed25519":
		if len(v.Secret) != ed25519.SeedSize {
			return nil, errors.New("invalid Ed25519 seed")
		}
		return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(v.Secret))
	case "ecdsa":
		var curve elliptic.Curve
		switch v.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("unsupported curve")
		}
		d := new(big.Int).SetBytes(v.Secret)
		if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
			return nil, errors.New("invalid ECDSA scalar")
		}
		x, y := curve.ScalarBaseMult(v.Secret)
		return ssh.NewSignerFromKey(&ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d})
	default:
		return nil, errors.New("unsupported compact key algorithm")
	}
}
