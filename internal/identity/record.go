package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/keyparse"
	"github.com/grexie/vault/internal/provider"
	"golang.org/x/crypto/ssh"
)

// Record exists only inside browser-encrypted account data and password backups.
// Server API models intentionally have no field of this type.
type Record struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Network   string    `json:"network,omitempty"`
	PublicKey string    `json:"publicKey"`
	Address   string    `json:"address,omitempty"`
	Secret    []byte    `json:"secret"`
	CreatedAt time.Time `json:"createdAt"`
	Owners    []string  `json:"owners,omitempty"`
	Threshold bool      `json:"threshold,omitempty"`
}

func newRecord(name, kind, network string) (Record, error) {
	if name != strings.TrimSpace(name) || len(name) < 1 || len(name) > 80 || strings.ContainsAny(name, "\n\r\x00") {
		return Record{}, errors.New("identity name must be 1–80 characters without control characters")
	}
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		return Record{}, e
	}
	return Record{ID: base64.RawURLEncoding.EncodeToString(b), Name: name, Type: kind, Network: network, CreatedAt: time.Now().UTC()}, nil
}

// Generate is invoked in the browser's Go/Wasm worker. No hosted API calls it.
func Generate(name, kind, network string) (Record, error) {
	switch kind {
	case "ssh":
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return Record{}, e
		}
		defer clear(key)
		block, e := ssh.MarshalPrivateKey(key, name)
		if e != nil {
			return Record{}, e
		}
		raw := pem.EncodeToMemory(block)
		defer clear(raw)
		return Import(name, kind, "", raw, nil)
	case "ethereum":
		key, e := crypto.GenerateKey()
		if e != nil {
			return Record{}, e
		}
		defer key.D.SetInt64(0)
		b := crypto.FromECDSA(key)
		defer clear(b)
		return Import(name, kind, "", []byte(hex.EncodeToString(b)), nil)
	case "bitcoin":
		params, e := BitcoinNetwork(network)
		if e != nil {
			return Record{}, e
		}
		key, e := btcec.NewPrivateKey()
		if e != nil {
			return Record{}, e
		}
		defer key.Zero()
		wif, e := btcutil.NewWIF(key, params, true)
		if e != nil {
			return Record{}, e
		}
		return Import(name, kind, network, []byte(wif.String()), nil)
	default:
		return Record{}, errors.New("identity type must be ssh, ethereum or bitcoin")
	}
}
func Import(name, kind, network string, raw, password []byte) (Record, error) {
	r, e := newRecord(name, kind, network)
	if e != nil {
		return r, e
	}
	switch kind {
	case "aws", "github", "cloudflare", "docker", "credentials", "login", "payment-card":
		c, e := provider.DecodeCredentials(raw)
		if e != nil {
			return r, e
		}
		if c.Provider != kind && (kind != "credentials" || c.Provider != network) {
			return r, errors.New("credential provider does not match identity type")
		}
		r.Secret, e = json.Marshal(c)
		if e != nil {
			return r, e
		}
		r.PublicKey = c.Provider
		r.Address = c.Provider
		if kind == "docker" {
			r.Address = c.Fields["username"] + " @ " + c.Fields["server"]
		}
		if kind == "github" {
			r.Address = "github.com"
		}
		if kind == "login" {
			r.Address = c.Fields["username"] + " @ " + c.Fields["origin"]
		}
		if kind == "payment-card" {
			n := c.Fields["number"]
			r.Address = "•••• " + n[len(n)-4:] + " · " + c.Fields["expiryMonth"] + "/" + c.Fields["expiryYear"]
		}
	case "ssh":
		key, e := keyparse.Parse(raw, password)
		if e != nil {
			return r, e
		}
		compact, e := keyparse.Compact(raw, password)
		if e != nil {
			return r, e
		}
		r.Secret = []byte(compact)
		r.PublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey())))
		r.Address = ssh.FingerprintSHA256(key.PublicKey())
	case "ethereum":
		key, e := EthereumKey(raw)
		if e != nil {
			return r, e
		}
		defer key.D.SetInt64(0)
		r.Secret = []byte(hex.EncodeToString(crypto.FromECDSA(key)))
		r.PublicKey = hex.EncodeToString(crypto.FromECDSAPub(&key.PublicKey))
		r.Address = crypto.PubkeyToAddress(key.PublicKey).Hex()
	case "bitcoin":
		key, e := BitcoinKey(strings.TrimSpace(string(raw)), network)
		if e != nil {
			return r, e
		}
		defer key.Zero()
		r.Secret = []byte(strings.TrimSpace(string(raw)))
		r.PublicKey = hex.EncodeToString(key.PubKey().SerializeCompressed())
		r.Address, e = BitcoinAddress(key.PubKey(), network)
		if e != nil {
			return r, e
		}
	default:
		return r, errors.New("identity type must be ssh, ethereum or bitcoin")
	}
	return r, nil
}

// Validate reconstructs public metadata from the secret, so backup metadata
// cannot mislabel a private key. Threshold shares use their protocol validator.
func Validate(r Record) error {
	if _, e := newRecord(r.Name, r.Type, r.Network); e != nil {
		return e
	}
	if r.Threshold {
		return errors.New("threshold shares require threshold validation")
	}
	if len(r.Owners) > 1 {
		return errors.New("imported keys cannot become threshold identities")
	}
	if r.Type == "ssh" {
		s, e := keyparse.Parse(r.Secret, nil)
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey()))) != r.PublicKey || ssh.FingerprintSHA256(s.PublicKey()) != r.Address {
			return errors.New("SSH backup public key mismatch")
		}
		return nil
	}
	v, e := Import(r.Name, r.Type, r.Network, r.Secret, nil)
	if e != nil {
		return e
	}
	if v.PublicKey != r.PublicKey || v.Address != r.Address {
		return errors.New("backup public identity does not match its private key")
	}
	return nil
}
