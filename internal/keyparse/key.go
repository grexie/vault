// Package keyparse is shared by the browser's Go/Wasm importer and the signer.
package keyparse

import (
	"bytes"
	"encoding/pem"
	"errors"

	"github.com/youmark/pkcs8"
	"golang.org/x/crypto/ssh"
)

func Parse(data, password []byte) (ssh.Signer, error) {
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte(`{"v":1,`)) {
		return parseCompact(data)
	}
	k, err := parseRaw(data, password)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(k)
}

func parseRaw(data, password []byte) (any, error) {
	if len(data) > 16384 || len(data) == 0 || len(password) > 1024 {
		return nil, errors.New("key file or passphrase is too large")
	}
	b, _ := pem.Decode(data)
	if b != nil && b.Type == "ENCRYPTED PRIVATE KEY" {
		k, e := pkcs8.ParsePKCS8PrivateKey(b.Bytes, password)
		if e != nil {
			return nil, errors.New("incorrect passphrase or unsupported encrypted PKCS#8 key")
		}
		return k, nil
	}
	if len(password) > 0 {
		k, e := ssh.ParseRawPrivateKeyWithPassphrase(data, password)
		if e == nil {
			return k, nil
		}
		// Accept an unencrypted file even if a password was unnecessarily supplied.
		if k, e2 := ssh.ParseRawPrivateKey(data); e2 == nil {
			return k, nil
		}
		return nil, errors.New("incorrect passphrase or unsupported SSH private key")
	}
	return ssh.ParseRawPrivateKey(data)
}
