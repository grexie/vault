package cloudstore

import (
	"errors"
	"io"
	"net/url"
	"os"
	"strings"
)

// ReadSecret accepts only a locally provisioned, owner-readable regular file.
// A missing or invalid key is fatal; generating a replacement at server startup
// would make existing records irrecoverable.
func ReadSecret(path string, max int) ([]byte, error) {
	if path == "" {
		return nil, errors.New("a local secret file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open local secret file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret must be a regular file readable only by its owner (0400 or 0600)")
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(max+1)))
	if err != nil || len(b) > max {
		clear(b)
		return nil, errors.New("invalid local secret file")
	}
	return b, nil
}

func ReadStorageKey(path string) ([]byte, error) {
	b, err := ReadSecret(path, 32)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		clear(b)
		return nil, errors.New("storage key file must contain exactly 32 random bytes")
	}
	return b, nil
}

func ValidateMongoURI(uri string, privatePlaintext bool) error {
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "mongodb" && u.Scheme != "mongodb+srv") || u.Host == "" {
		return errors.New("invalid MongoDB connection configuration")
	}
	q := u.Query()
	for name, values := range q {
		n := strings.ToLower(name)
		for _, value := range values {
			if (n == "tlsinsecure" || n == "tlsallowinvalidcertificates" || n == "tlsallowinvalidhostnames") && value != "false" {
				return errors.New("MongoDB TLS certificate verification must remain enabled")
			}
		}
	}
	tls := u.Scheme == "mongodb+srv"
	var explicitTLS *bool
	for name, values := range q {
		if strings.EqualFold(name, "tls") || strings.EqualFold(name, "ssl") {
			for _, value := range values {
				if value != "true" && value != "false" {
					return errors.New("MongoDB TLS option must be true or false")
				}
				enabled := value == "true"
				if explicitTLS != nil && *explicitTLS != enabled {
					return errors.New("conflicting MongoDB TLS options")
				}
				explicitTLS = &enabled
				tls = enabled
			}
		}
	}
	if !tls && !privatePlaintext {
		return errors.New("MongoDB TLS is required; private plaintext requires explicit local configuration")
	}
	return nil
}
