package vaultwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func canonicalReviewRequest() Request {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	return Request{ID: "review-request", DeviceID: "review-client", AgentID: "review-agent", Session: "offline-review", Reason: "Approve an offline synthetic test", Kind: "wallet-sign", Identity: "Fixture identity", IdentityType: "ethereum", Network: "0x1", Payload: []byte(`{"reviewed":"benign"}`), Duration: 60, CreatedAt: now, ExpiresAt: now.Add(time.Minute), Managed: true}
}

func appendRequestMember(raw []byte, name string, value json.RawMessage) []byte {
	key, _ := json.Marshal(name)
	b := append([]byte{}, raw[:len(raw)-1]...)
	b = append(b, ',')
	b = append(b, key...)
	b = append(b, ':')
	b = append(b, value...)
	return append(b, '}')
}

func TestSignedRequestRejectsBrowserGoPayloadSubstitution(t *testing.T) {
	q := canonicalReviewRequest()
	raw, _ := json.Marshal(q)
	malicious := []byte(`{"reviewed":"malicious substituted operation"}`)
	value, _ := json.Marshal(malicious)
	raw = appendRequestMember(raw, "Payload", value)
	// Reproduce the old interpretation split without relying on a live browser:
	// JSON object lookup is case-sensitive; Go's struct decoder is not.
	var browser map[string]json.RawMessage
	var oldGo Request
	if json.Unmarshal(raw, &browser) != nil || json.Unmarshal(raw, &oldGo) != nil {
		t.Fatal("invalid exploit fixture")
	}
	var displayed []byte
	if json.Unmarshal(browser["payload"], &displayed) != nil || !bytes.Equal(displayed, q.Payload) || !bytes.Equal(oldGo.Payload, malicious) {
		t.Fatal("fixture did not produce the former browser/Go interpretation split")
	}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignBytes(key.Bytes(), "request", raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeRequest(raw); err == nil {
		t.Fatal("ambiguous request accepted by the browser/agent decoder")
	}
	for _, target := range []any{&Request{}, &map[string]any{}} {
		if err = Verify(key.PublicKey().Bytes(), "request", signed, target); err == nil {
			t.Fatal("cryptographically valid ambiguous request accepted by signature verification")
		}
	}
}

func TestSignedRequestRejectsEveryFieldAliasAndDuplicate(t *testing.T) {
	raw, _ := json.Marshal(canonicalReviewRequest())
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 14 {
		t.Fatal("fixture must exercise every signed request field")
	}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, altered []byte) {
		t.Helper()
		if _, err := DecodeRequest(altered); err == nil {
			t.Fatal("ambiguous request decoded")
		}
		signed, err := SignBytes(key.Bytes(), "request", altered)
		if err != nil {
			t.Fatal(err)
		}
		var parsed Request
		if Verify(key.PublicKey().Bytes(), "request", signed, &parsed) == nil {
			t.Fatal("ambiguous signed request verified")
		}
	}
	for name, value := range fields {
		t.Run(name+"/duplicate", func(t *testing.T) { check(t, appendRequestMember(raw, name, value)) })
		aliases := map[string]bool{strings.ToUpper(name): true}
		for i := range name {
			part := name[i : i+1]
			flipped := strings.ToUpper(part)
			if flipped == part {
				flipped = strings.ToLower(part)
			}
			aliases[name[:i]+flipped+name[i+1:]] = true
		}
		delete(aliases, name)
		for alias := range aliases {
			t.Run(name+"/alias-"+alias, func(t *testing.T) {
				canonicalKey, _ := json.Marshal(name)
				aliasKey, _ := json.Marshal(alias)
				check(t, bytes.Replace(raw, append(canonicalKey, ':'), append(aliasKey, ':'), 1))
				check(t, appendRequestMember(raw, alias, value))
			})
		}
	}
	for name, altered := range map[string][]byte{
		"unknown":           appendRequestMember(raw, "futureSigningPermission", json.RawMessage(`true`)),
		"empty-name":        appendRequestMember(raw, "", json.RawMessage(`null`)),
		"escaped-duplicate": []byte(strings.TrimSuffix(string(raw), "}") + `,"pay\u006coad":"` + base64.StdEncoding.EncodeToString([]byte("replacement")) + `"}`),
		"trailing-object":   append(append([]byte{}, raw...), []byte(` {}`)...),
		"array":             append(append([]byte{'['}, raw...), ']'),
		"null":              []byte(`null`), "invalid-utf8": append([]byte{0xff}, raw...),
	} {
		t.Run(name, func(t *testing.T) { check(t, altered) })
	}
}

func TestSignedRequestCanonicalDecoderCoversEveryOperation(t *testing.T) {
	kinds := []string{"ssh", "age", "ethereum", "bitcoin", "hyperliquid", "wallet-sign", "wallet-connect", "create", "import", "lookup", "keychain-import", "credentials", "api", "autofill"}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			q := canonicalReviewRequest()
			q.Kind = kind
			switch kind {
			case "ssh", "age":
				q.IdentityType = "ssh"
			case "bitcoin":
				q.IdentityType = "bitcoin"
			case "hyperliquid":
				q.Network = "testnet"
			case "wallet-connect":
				q.Managed, q.AgentID = false, q.DeviceID
				q.Payload = []byte(`{"origin":"https://offline.example","operation":"connect","chain":{"chainId":"0x1","chainName":"Fixture","nativeCurrency":{"name":"Ether","symbol":"ETH","decimals":18},"rpcUrls":["https://rpc.example"]}}`)
			case "keychain-import":
				q.IdentityType = "login"
			case "credentials", "api":
				q.IdentityType = "github"
				q.Payload = []byte(`{"provider":"github"}`)
			case "autofill":
				q.IdentityType = "login"
				q.Payload = []byte(`{"provider":"login"}`)
			}
			if err := ValidateRequest(q); err != nil {
				t.Fatal("invalid operation fixture", err)
			}
			raw, _ := json.Marshal(q)
			decoded, err := DecodeRequest(raw)
			if err != nil || !reflect.DeepEqual(decoded, q) {
				t.Fatal("canonical request changed", err)
			}
			signed, _ := SignBytes(key.Bytes(), "request", raw)
			var verified Request
			if err := Verify(key.PublicKey().Bytes(), "request", signed, &verified); err != nil || !reflect.DeepEqual(verified, q) {
				t.Fatal("canonical signed request rejected", err)
			}
			value, _ := json.Marshal([]byte("substituted operation"))
			for _, field := range []string{"Payload", "payload"} {
				attack, _ := SignBytes(key.Bytes(), "request", appendRequestMember(raw, field, value))
				if Verify(key.PublicKey().Bytes(), "request", attack, &Request{}) == nil {
					t.Fatal("operation accepted payload ambiguity", field)
				}
			}
		})
	}
}
