package walletsign

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const MaxPayload = 192 * 1024

// StrictJSON retains integer precision and rejects duplicates, case aliases,
// excessive nesting and invalid UTF-8 before any signing decoder sees the data.
func StrictJSON(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > MaxPayload || !utf8.Valid(raw) {
		return nil, errors.New("invalid or oversized wallet payload")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	v, e := readJSON(d, 0, &nodes)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing wallet JSON")
	}
	return v, nil
}
func readJSON(d *json.Decoder, depth int, nodes *int) (any, error) {
	*nodes++
	if depth > 32 || *nodes > 10000 {
		return nil, errors.New("wallet JSON exceeds structural limits")
	}
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				s, ok := k.(string)
				if !ok || len(s) > 256 || seen[strings.ToLower(s)] {
					return nil, errors.New("duplicate wallet JSON member")
				}
				seen[strings.ToLower(s)] = true
				v, e := readJSON(d, depth+1, nodes)
				if e != nil {
					return nil, e
				}
				m[s] = v
			}
			_, e := d.Token()
			return m, e
		case '[':
			a := []any{}
			for d.More() {
				v, e := readJSON(d, depth+1, nodes)
				if e != nil {
					return nil, e
				}
				a = append(a, v)
			}
			_, e := d.Token()
			return a, e
		default:
			return nil, errors.New("invalid JSON delimiter")
		}
	}
	return t, nil
}
func exact(m map[string]any, names ...string) error {
	allow := map[string]bool{}
	for _, n := range names {
		allow[n] = true
	}
	for n := range m {
		if !allow[n] {
			return errors.New("unknown or noncanonical wallet field")
		}
	}
	return nil
}
