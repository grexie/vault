//go:build unix

package command

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/identity"
	"github.com/grexie/vault/internal/vaultwire"
)

func TestEthereumImportInput(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.D.SetInt64(0)
	raw := hex.EncodeToString(crypto.FromECDSA(key))
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()
	for _, input := range []string{raw, "0x" + raw + "\n"} {
		r, err := readEthereumImport(strings.NewReader(input), "deployer", strings.ToLower(address))
		if err != nil || r.Type != "ethereum" || r.Address != address || r.Network != "" || string(r.Secret) != raw {
			t.Fatal("valid key import did not preserve its identity")
		}
		clear(r.Secret)
	}
	for _, tc := range []struct{ input, address string }{
		{raw, "0x0000000000000000000000000000000000000001"},
		{raw, "invalid"},
		{"", address},
		{strings.Repeat("0", 64), address},
		{strings.Repeat("f", 64), address},
		{"malformed-sensitive-input", address},
		{raw + strings.Repeat(" ", 1025), address},
		{raw + "\n" + raw, address},
	} {
		r, err := readEthereumImport(strings.NewReader(tc.input), "deployer", tc.address)
		if err == nil || len(r.Secret) != 0 {
			t.Fatal("invalid input accepted or retained")
		}
		if tc.input != "" && strings.Contains(err.Error(), tc.input) {
			t.Fatal("error exposed private input")
		}
	}
}

func TestEthereumImportRejectsKeyArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--name", "test", "--private-key=private-material"},
		{"--name", "test", "--stdin", "private-material"},
		{"--name", "test"},
	} {
		err := importEthereumVault(context.Background(), vaultOptions{}, args)
		if err == nil || strings.Contains(err.Error(), "private-material") {
			t.Fatal("invalid arguments accepted or exposed")
		}
	}
}

// Exercise the actual submission and signed completion. The simulated relay sees
// only ciphertext; a distinct pinned owner key decrypts it to review and approve.
func TestIdentityImportEncryptedApproval(t *testing.T) {
	type importCase struct{ kind, outcome string }
	var cases []importCase
	for _, kind := range []string{"ethereum", "github", "credentials"} {
		for _, outcome := range []string{"success", "declined", "wrong-address", "wrong-name", "wrong-type", "wrong-network", "wrong-public-key", "unsigned", "secret-in-reply"} {
			cases = append(cases, importCase{kind, outcome})
		}
	}
	for _, tc := range cases {
		t.Run(tc.kind+"/"+tc.outcome, func(t *testing.T) {
			var record identity.Record
			var err error
			switch tc.kind {
			case "ethereum":
				record, err = identity.Generate("deployer", "ethereum", "")
			case "github":
				record, err = identity.Import("work-account", "github", "github", []byte(`{"provider":"github","fields":{"token":"fixture-import-token"}}`), nil)
			case "credentials":
				record, err = identity.Import("custom-service", "credentials", "example", []byte(`{"provider":"example","fields":{"username":"fixture-user","password":"fixture-import-password"}}`), nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer clear(record.Secret)
			owner, _ := vaultwire.NewKey()
			boxKey, _ := vaultwire.NewKey()
			config, err := device.NewConfig("http://127.0.0.1", "fixture")
			if err != nil {
				t.Fatal(err)
			}
			config.OwnerID = "owner"
			config.OwnerPublic = owner.PublicKey().Bytes()
			config.OwnerBoxPublic = boxKey.PublicKey().Bytes()
			var submitted vaultwire.Signed
			var q vaultwire.Request
			revoked := make(chan bool, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/device/requests" {
					body, _ := io.ReadAll(r.Body)
					if bytes.Contains(body, record.Secret) || bytes.Contains(body, []byte(base64.StdEncoding.EncodeToString(record.Secret))) {
						t.Error("private key escaped encryption")
					}
					var in struct {
						Signed vaultwire.Signed `json:"signed"`
					}
					if json.Unmarshal(body, &in) != nil || vaultwire.Verify(config.Device.PublicKey, "request", in.Signed, &q) != nil {
						t.Error("invalid signed import request")
					}
					submitted = in.Signed
					if q.Kind != "import" || q.IdentityType != record.Type || q.Identity != record.Name || q.Managed || q.Network != record.Network || vaultwire.ValidateRequest(q) != nil {
						t.Error("import changed identity or operation")
					}
					var box vaultwire.Envelope
					if json.Unmarshal(q.Payload, &box) != nil {
						t.Error("import payload is not an envelope")
					}
					plain, err := vaultwire.Open(boxKey.Bytes(), "import:"+config.Device.ID, box)
					if err != nil {
						t.Error("pinned owner could not open import")
					}
					defer clear(plain)
					var imported identity.Record
					if json.Unmarshal(plain, &imported) != nil || imported.ID != record.ID || imported.Name != record.Name || imported.Type != record.Type || imported.Network != record.Network || imported.Address != record.Address || imported.PublicKey != record.PublicKey || !bytes.Equal(imported.Secret, record.Secret) {
						t.Error("encrypted identity did not survive import")
					}
					clear(imported.Secret)
					if _, err := vaultwire.Open(config.BoxPrivate, "import:"+config.Device.ID, box); err == nil {
						t.Error("import decryptable by a non-owner key")
					}
					io.WriteString(w, "{}")
					return
				}
				if r.URL.Path == "/api/v1/device/requests/"+q.ID+"/revoke" {
					revoked <- true
					io.WriteString(w, "{}")
					return
				}
				if r.URL.Path != "/api/v1/device/requests/"+q.ID {
					http.NotFound(w, r)
					return
				}
				public := record
				public.Secret = nil
				switch tc.outcome {
				case "wrong-address":
					public.Address = "0x0000000000000000000000000000000000000001"
				case "wrong-name":
					public.Name = "other"
				case "wrong-type":
					public.Type = "ssh"
				case "wrong-network":
					public.Network = "other-provider"
				case "wrong-public-key":
					public.PublicKey = "other-public-key"
				case "secret-in-reply":
					public.Secret = record.Secret
				}
				result, _ := json.Marshal(public)
				defer clear(result)
				response, _ := vaultwire.Sign(owner.Bytes(), "response", vaultwire.Response{RequestID: q.ID, RequestHash: vaultwire.Digest(submitted.Payload), Result: result, ExpiresAt: time.Now().Add(time.Minute)})
				state := vaultwire.RequestState{Status: "completed", Response: &response}
				if tc.outcome == "declined" {
					state.Status = "declined"
				}
				if tc.outcome == "unsigned" {
					state.Response = nil
				}
				json.NewEncoder(w).Encode(state)
			}))
			defer server.Close()
			config.Server = server.URL
			client := device.New(config)
			err = approveIdentityImport(context.Background(), client, vaultOptions{Reason: "fixture import", Timeout: time.Second}, record)
			if (err == nil) != (tc.outcome == "success") {
				t.Fatalf("unexpected import result: %v", err)
			}
			select {
			case <-revoked:
			default:
				t.Fatal("import request was not closed")
			}
		})
	}
}
