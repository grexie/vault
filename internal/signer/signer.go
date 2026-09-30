// Package signer owns per-grant subprocesses. Only the subprocess decrypts a key;
// it never writes key material to disk or returns it to the CLI or HTTP server.
package signer

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/grexie/vault/internal/access"
	"github.com/grexie/vault/internal/keyparse"
	"github.com/grexie/vault/internal/limits"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const MaxMessage = 128 * 1024

type Envelope struct {
	PublicKey  []byte `json:"publicKey"`
	Salt       []byte `json:"salt"`
	IV         []byte `json:"iv"`
	Ciphertext []byte `json:"ciphertext"`
}

type Message struct {
	Action      string               `json:"action"`
	IdleSeconds int                  `json:"idleSeconds,omitempty"`
	Access      string               `json:"access,omitempty"`
	Envelope    *Envelope            `json:"envelope,omitempty"`
	ExpiresAt   time.Time            `json:"expiresAt,omitempty"`
	Data        []byte               `json:"data,omitempty"`
	Key         []byte               `json:"key,omitempty"`
	Flags       agent.SignatureFlags `json:"flags,omitempty"`
}

type Reply struct {
	PublicKey []byte         `json:"publicKey,omitempty"`
	FileKey   []byte         `json:"fileKey,omitempty"`
	Signature *ssh.Signature `json:"signature,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// OperationError is a rejected operation from a live worker, not worker failure.
type OperationError struct{ Message string }

func (e *OperationError) Error() string { return e.Message }

type Worker struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	in        io.WriteCloser
	out       *bufio.Scanner
	PublicKey []byte
	closed    bool
}

func Start(executable, id, fingerprint string, hardDeadline time.Time) (*Worker, error) {
	cmd := exec.Command(executable, "_signer", id, fingerprint, fmt.Sprint(hardDeadline.Unix()))
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		in.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		in.Close()
		return nil, err
	}
	w := &Worker{cmd: cmd, in: in, out: bufio.NewScanner(out)}
	w.out.Buffer(make([]byte, 4096), MaxMessage)
	startupTimer := time.AfterFunc(5*time.Second, func() { _ = cmd.Process.Kill() })
	r, err := w.read()
	startupTimer.Stop()
	if err != nil {
		w.Close()
		return nil, err
	}
	w.PublicKey = r.PublicKey
	return w, nil
}

func (w *Worker) read() (Reply, error) {
	if !w.out.Scan() {
		return Reply{}, errors.New("signer unavailable")
	}
	var r Reply
	if err := json.Unmarshal(w.out.Bytes(), &r); err != nil {
		return r, err
	}
	if r.Error != "" {
		return r, &OperationError{Message: r.Error}
	}
	return r, nil
}

func (w *Worker) Do(m Message) (Reply, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return Reply{}, errors.New("signer closed")
	}
	// A wedged worker must never hold a revoke or request lock indefinitely.
	timer := time.AfterFunc(5*time.Second, func() { _ = w.cmd.Process.Kill() })
	defer timer.Stop()
	if err := json.NewEncoder(w.in).Encode(m); err != nil {
		return Reply{}, err
	}
	return w.read()
}

func (w *Worker) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	_ = w.cmd.Process.Kill()
	_ = w.in.Close()
	_ = w.cmd.Wait() // Reap the key-holding process before reporting revocation.
}

func Context(id, fingerprint string) []byte {
	return []byte("remote-ssh-agent/lease/v1:" + id + ":" + fingerprint)
}

func decrypt(priv *ecdh.PrivateKey, e Envelope, aad []byte) ([]byte, error) {
	if len(e.IV) != 12 || len(e.Salt) != 32 || len(e.Ciphertext) > 32768 {
		return nil, errors.New("invalid envelope")
	}
	pub, err := ecdh.P256().NewPublicKey(e.PublicKey)
	if err != nil {
		return nil, err
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	key := make([]byte, 32)
	defer clear(key)
	if _, err = io.ReadFull(hkdf.New(sha256.New, secret, e.Salt, aad), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, e.IV, e.Ciphertext, aad)
}

// Serve runs only in the hidden child-process command. EOF, hard deadline,
// expiry, or the parent killing the process destroys the live signer.
func Serve(id, fingerprint string, hardDeadline time.Time, in io.Reader, out io.Writer) error {
	persistent := hardDeadline.IsZero()
	if !persistent && (time.Until(hardDeadline) <= 0 || time.Until(hardDeadline) > limits.MaxLeaseDuration+5*time.Minute) {
		return errors.New("invalid signer deadline")
	}
	initialTTL := time.Until(hardDeadline)
	if persistent {
		initialTTL = 3 * time.Minute
	}
	timer := time.AfterFunc(initialTTL, func() { os.Exit(0) })
	defer timer.Stop()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	if err := enc.Encode(Reply{PublicKey: priv.PublicKey().Bytes()}); err != nil {
		return err
	}
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 4096), MaxMessage)
	var key ssh.Signer
	var ageKey age.Identity
	var allowed string
	var expires time.Time
	var idle time.Duration
	for scan.Scan() {
		var m Message
		if err := json.Unmarshal(scan.Bytes(), &m); err != nil {
			return err
		}
		var r Reply
		switch {
		case m.Action == "unlock" && key == nil && m.Envelope != nil:
			if persistent && !m.ExpiresAt.IsZero() || !persistent && (m.ExpiresAt.After(hardDeadline) || !m.ExpiresAt.After(time.Now())) {
				return errors.New("invalid expiry")
			}
			plain, err := decrypt(priv, *m.Envelope, Context(id, fingerprint))
			if err != nil {
				return errors.New("key envelope could not be opened")
			}
			var payload struct {
				Key        string `json:"key"`
				Passphrase string `json:"passphrase"`
			}
			err = json.Unmarshal(plain, &payload)
			clear(plain)
			if err != nil {
				return errors.New("invalid key payload")
			}
			pem := []byte(payload.Key)
			pass := []byte(payload.Passphrase)
			raw, parseErr := keyparse.ParseRaw(pem, pass)
			err = parseErr
			if err == nil {
				key, err = ssh.NewSignerFromKey(raw)
			}
			clear(pem)
			clear(pass)
			payload.Key = ""
			payload.Passphrase = ""
			priv = nil
			if err != nil {
				return errors.New("SSH key or passphrase is invalid")
			}
			if ssh.FingerprintSHA256(key.PublicKey()) != fingerprint {
				return errors.New("SSH key fingerprint mismatch")
			}
			allowed, err = access.Normalize(m.Access)
			if err != nil {
				return err
			}
			if access.AllowsAge(allowed) {
				switch k := raw.(type) {
				case ed25519.PrivateKey:
					ageKey, err = agessh.NewEd25519Identity(k)
				case *ed25519.PrivateKey:
					ageKey, err = agessh.NewEd25519Identity(*k)
				case *rsa.PrivateKey:
					ageKey, err = agessh.NewRSAIdentity(k)
				default:
					return errors.New("age requires an RSA or Ed25519 SSH key")
				}
				if err != nil {
					return errors.New("SSH key cannot be used with age")
				}
			}
			expires = m.ExpiresAt
			if persistent {
				idle = time.Duration(m.IdleSeconds) * time.Second
				if idle < time.Second || idle > limits.MaxIdleDuration {
					return errors.New("invalid inactivity timeout")
				}
				expires = time.Now().Add(idle)
				timer.Reset(idle)
			} else {
				timer.Reset(time.Until(expires))
			}
			r.PublicKey = key.PublicKey().Marshal()
		case key != nil && persistent && time.Now().Before(expires) && m.Action == "touch":
			expires = time.Now().Add(idle)
			timer.Reset(idle)
		case key != nil && time.Now().Before(expires) && access.AllowsSSH(allowed) && m.Action == "list":
			r.PublicKey = key.PublicKey().Marshal()
		case key != nil && time.Now().Before(expires) && access.AllowsSSH(allowed) && m.Action == "sign":
			if len(m.Data) > 32768 || len(m.Data) == 0 || base64.StdEncoding.EncodeToString(m.Key) != base64.StdEncoding.EncodeToString(key.PublicKey().Marshal()) {
				return errors.New("invalid signing request")
			}
			var sig *ssh.Signature
			if key.PublicKey().Type() == ssh.KeyAlgoRSA {
				// Do not permit legacy SHA-1 ssh-rsa signatures.
				alg := ""
				switch m.Flags {
				case agent.SignatureFlagRsaSha256:
					alg = ssh.KeyAlgoRSASHA256
				case agent.SignatureFlagRsaSha512:
					alg = ssh.KeyAlgoRSASHA512
				}
				if alg == "" {
					r.Error = "RSA requires SHA-256 or SHA-512"
					break
				}
				sig, err = key.(ssh.AlgorithmSigner).SignWithAlgorithm(rand.Reader, m.Data, alg)
			} else {
				if m.Flags != 0 {
					r.Error = "invalid signature flags"
					break
				}
				sig, err = key.Sign(rand.Reader, m.Data)
			}
			if err != nil {
				return errors.New("signing failed")
			}
			r.Signature = sig
			if persistent {
				expires = time.Now().Add(idle)
				timer.Reset(idle)
			}
		case ageKey != nil && time.Now().Before(expires) && access.AllowsAge(allowed) && m.Action == "age-decrypt":
			if len(m.Data) == 0 || len(m.Data) > limits.MaxAgeHeader {
				r.Error = "invalid age header"
				break
			}
			r.FileKey, err = age.DecryptHeader(m.Data, ageKey)
			if err != nil {
				r.Error = "age header is invalid or encrypted to a different key"
			}
		default:
			r.Error = "signer locked"
		}
		if err := enc.Encode(r); err != nil {
			clear(r.FileKey)
			return err
		}
		clear(r.FileKey)
	}
	return scan.Err()
}
