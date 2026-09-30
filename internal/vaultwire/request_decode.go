package vaultwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// DecodeRequest rejects interpretations that differ between JSON.parse and
// encoding/json. The bytes are signed, but Go's default struct decoder treats
// field names case-insensitively; accepting e.g. payload and Payload would let
// a requester obtain approval for different data from the data the agent uses.
func DecodeRequest(raw []byte) (Request, error) {
	var q Request
	if len(raw) > 16*1024*1024 || !utf8.Valid(raw) {
		return q, errors.New("invalid signed request encoding")
	}
	allowed := map[string]bool{}
	for _, name := range []string{"id", "deviceId", "agentId", "session", "reason", "kind", "identity", "identityType", "network", "payload", "duration", "createdAt", "expiresAt", "managed"} {
		allowed[name] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, e := d.Token()
	if e != nil || first != json.Delim('{') {
		return q, errors.New("signed request must be an object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, e := d.Token()
		name, ok := token.(string)
		if e != nil || !ok || !allowed[name] || seen[name] {
			return q, errors.New("duplicate or noncanonical signed request field")
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return q, errors.New("invalid signed request field")
		}
	}
	if _, e = d.Token(); e != nil {
		return q, e
	}
	if _, e = d.Token(); e != io.EOF {
		return q, errors.New("trailing signed request data")
	}
	if e = json.Unmarshal(raw, &q); e != nil {
		return q, errors.New("invalid signed request")
	}
	return q, nil
}
