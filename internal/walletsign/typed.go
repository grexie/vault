package walletsign

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type typedField struct{ Name, Type string }
type typedData struct {
	Types           map[string][]typedField
	Primary         string
	Domain, Message map[string]any
	Version         int
}

var typeNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_:]{0,127}$`)
var identPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
var numberPattern = regexp.MustCompile(`^-?(0x[0-9a-fA-F]+|[0-9]+)$`)

func parseTyped(raw []byte, version int) (typedData, error) {
	out := typedData{Types: map[string][]typedField{}, Version: version}
	v, e := StrictJSON(raw)
	if e != nil {
		return out, e
	}
	m, ok := v.(map[string]any)
	if !ok || exact(m, "types", "primaryType", "domain", "message") != nil || len(m) != 4 {
		return out, errors.New("typed data requires types, primaryType, domain and message")
	}
	out.Primary, _ = m["primaryType"].(string)
	out.Domain, ok = m["domain"].(map[string]any)
	if !ok {
		return out, errors.New("invalid typed domain")
	}
	out.Message, ok = m["message"].(map[string]any)
	if !ok {
		return out, errors.New("invalid typed message")
	}
	types, ok := m["types"].(map[string]any)
	if !ok || len(types) > 64 {
		return out, errors.New("invalid typed definitions")
	}
	for name, v := range types {
		if !typeNamePattern.MatchString(name) {
			return out, errors.New("invalid typed name")
		}
		fs, ok := v.([]any)
		if !ok || len(fs) > 64 {
			return out, errors.New("invalid typed fields")
		}
		seen := map[string]bool{}
		out.Types[name] = []typedField{}
		for _, v := range fs {
			f, ok := v.(map[string]any)
			if !ok || len(f) != 2 || exact(f, "name", "type") != nil {
				return out, errors.New("invalid typed field")
			}
			n, _ := f["name"].(string)
			typ, _ := f["type"].(string)
			if !identPattern.MatchString(n) || len(typ) > 256 || seen[n] {
				return out, errors.New("invalid or duplicate typed field")
			}
			seen[n] = true
			out.Types[name] = append(out.Types[name], typedField{n, typ})
		}
	}
	if _, ok := out.Types["EIP712Domain"]; !ok {
		return out, errors.New("missing EIP712Domain definition")
	}
	if _, ok := out.Types[out.Primary]; !ok {
		return out, errors.New("missing primary type")
	}
	for _, fs := range out.Types {
		for _, f := range fs {
			if e = out.validType(f.Type, 0); e != nil {
				return out, e
			}
		}
	}
	return out, nil
}
func splitArray(typ string) (base string, length int, array bool, err error) {
	if !strings.HasSuffix(typ, "]") {
		return typ, 0, false, nil
	}
	i := strings.LastIndex(typ, "[")
	if i <= 0 {
		return "", 0, false, errors.New("invalid array type")
	}
	n := typ[i+1 : len(typ)-1]
	if n == "" {
		return typ[:i], -1, true, nil
	}
	size, e := strconv.Atoi(n)
	if e != nil || size < 1 || size > 2048 || strconv.Itoa(size) != n {
		return "", 0, false, errors.New("invalid array length")
	}
	return typ[:i], size, true, nil
}
func primitiveSize(typ string) (string, int, error) {
	if typ == "address" || typ == "bool" || typ == "string" || typ == "bytes" {
		return typ, 0, nil
	}
	for _, prefix := range []string{"uint", "int", "bytes"} {
		if strings.HasPrefix(typ, prefix) {
			n, e := strconv.Atoi(strings.TrimPrefix(typ, prefix))
			if e != nil {
				return "", 0, errors.New("invalid primitive type")
			}
			if prefix == "bytes" {
				if n >= 1 && n <= 32 {
					return prefix, n, nil
				}
			} else if n >= 8 && n <= 256 && n%8 == 0 {
				return prefix, n, nil
			}
			return "", 0, errors.New("invalid primitive width")
		}
	}
	return "", 0, errors.New("unsupported typed primitive")
}
func (t typedData) validType(typ string, depth int) error {
	if depth > 8 {
		return errors.New("typed arrays exceed nesting limit")
	}
	base, _, arr, e := splitArray(typ)
	if e != nil {
		return e
	}
	if arr {
		if t.Version == 3 {
			return errors.New("EIP-712 v3 does not support arrays; use v4")
		}
		return t.validType(base, depth+1)
	}
	if _, ok := t.Types[typ]; ok {
		return nil
	}
	_, _, e = primitiveSize(typ)
	return e
}
func (t typedData) typeHash(primary string) []byte {
	seen := map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		for _, f := range t.Types[name] {
			base := strings.Split(f.Type, "[")[0]
			if _, ok := t.Types[base]; ok {
				visit(base)
			}
		}
	}
	visit(primary)
	delete(seen, primary)
	others := []string{}
	for n := range seen {
		others = append(others, n)
	}
	sort.Strings(others)
	names := append([]string{primary}, others...)
	var s strings.Builder
	for _, n := range names {
		s.WriteString(n + "(")
		for i, f := range t.Types[n] {
			if i > 0 {
				s.WriteByte(',')
			}
			s.WriteString(f.Type + " " + f.Name)
		}
		s.WriteByte(')')
	}
	return crypto.Keccak256([]byte(s.String()))
}
func (t typedData) hashStruct(name string, v map[string]any, depth int) ([]byte, error) {
	if depth > 32 {
		return nil, errors.New("typed message exceeds nesting limit")
	}
	fs := t.Types[name]
	// EIP-712 hashes declared fields only. Some wallets (including Hyperliquid)
	// supply additional protocol metadata. Review projects declared fields and
	// separately identifies every ignored field; never describe those as signed.
	b := t.typeHash(name)
	for _, f := range fs {
		value, exists := v[f.Name]
		if !exists && t.Version == 3 {
			continue
		}
		encoded, e := t.encode(f.Type, value, depth+1)
		if e != nil {
			return nil, fmt.Errorf("typed field %s: %w", f.Name, e)
		}
		b = append(b, encoded...)
	}
	return crypto.Keccak256(b), nil
}

func (t typedData) project(name string, v map[string]any, path string, ignored *[]string, depth int) map[string]any {
	out := map[string]any{}
	if depth > 32 {
		return out
	}
	seen := map[string]bool{}
	var projectValue func(string, any, string, int) any
	projectValue = func(typ string, value any, path string, depth int) any {
		if depth > 32 {
			return nil
		}
		base, _, arr, _ := splitArray(typ)
		if arr {
			if vs, ok := value.([]any); ok {
				result := []any{}
				for i, x := range vs {
					result = append(result, projectValue(base, x, fmt.Sprintf("%s[%d]", path, i), depth+1))
				}
				return result
			}
		}
		if _, ok := t.Types[typ]; ok {
			if m, ok := value.(map[string]any); ok {
				return t.project(typ, m, path, ignored, depth+1)
			}
		}
		return value
	}
	for _, f := range t.Types[name] {
		seen[f.Name] = true
		if value, ok := v[f.Name]; ok {
			out[f.Name] = projectValue(f.Type, value, path+"."+f.Name, depth+1)
		}
	}
	for k := range v {
		if !seen[k] {
			*ignored = append(*ignored, path+"."+k)
		}
	}
	return out
}
func (t typedData) encode(typ string, v any, depth int) ([]byte, error) {
	if depth > 32 {
		return nil, errors.New("typed value exceeds nesting limit")
	}
	base, n, arr, e := splitArray(typ)
	if e != nil {
		return nil, e
	}
	if arr {
		values, ok := v.([]any)
		if !ok || len(values) > 2048 || n >= 0 && len(values) != n {
			return nil, errors.New("invalid typed array")
		}
		b := []byte{}
		for _, v := range values {
			x, e := t.encode(base, v, depth+1)
			if e != nil {
				return nil, e
			}
			b = append(b, x...)
		}
		return crypto.Keccak256(b), nil
	}
	if _, ok := t.Types[typ]; ok {
		if v == nil && t.Version == 4 {
			return make([]byte, 32), nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("expected typed object")
		}
		return t.hashStruct(typ, m, depth+1)
	}
	return primitive(typ, v)
}
func parseInteger(v any) (*big.Int, error) {
	var s string
	switch n := v.(type) {
	case string:
		s = n
	case json.Number:
		s = string(n)
	default:
		return nil, errors.New("integer must be a string or exact JSON integer")
	}
	if len(s) > 100 || !numberPattern.MatchString(s) {
		return nil, errors.New("invalid integer")
	}
	negative := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	base := 10
	if strings.HasPrefix(s, "0x") {
		base = 16
		s = s[2:]
	}
	n, ok := new(big.Int).SetString(s, base)
	if !ok {
		return nil, errors.New("invalid integer")
	}
	if negative {
		n.Neg(n)
	}
	return n, nil
}
func hexBytes(v any) ([]byte, error) {
	s, ok := v.(string)
	if !ok || !strings.HasPrefix(s, "0x") || len(s)%2 != 0 {
		return nil, errors.New("expected even-length 0x hexadecimal bytes")
	}
	b, e := hex.DecodeString(s[2:])
	if e != nil {
		return nil, errors.New("invalid hexadecimal bytes")
	}
	return b, nil
}
func primitive(typ string, v any) ([]byte, error) {
	kind, size, e := primitiveSize(typ)
	if e != nil {
		return nil, e
	}
	word := make([]byte, 32)
	switch kind {
	case "string":
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("expected string")
		}
		return crypto.Keccak256([]byte(s)), nil
	case "bytes":
		b, e := hexBytes(v)
		if e != nil {
			return nil, e
		}
		if size == 0 {
			return crypto.Keccak256(b), nil
		}
		if len(b) != size {
			return nil, errors.New("fixed bytes length mismatch")
		}
		copy(word, b)
	case "address":
		s, ok := v.(string)
		if !ok || len(s) != 42 || !strings.HasPrefix(s, "0x") || !common.IsHexAddress(s) {
			return nil, errors.New("invalid typed address")
		}
		copy(word[12:], common.HexToAddress(s).Bytes())
	case "bool":
		if v == true || v == "true" {
			word[31] = 1
		} else if v != false && v != "false" {
			return nil, errors.New("ambiguous typed boolean")
		}
	case "int", "uint":
		n, e := parseInteger(v)
		if e != nil {
			return nil, e
		}
		bits := size
		if kind == "int" {
			bits--
		}
		limit := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		if n.Sign() < 0 {
			if kind != "int" || n.Cmp(new(big.Int).Neg(limit)) < 0 {
				return nil, errors.New("typed integer out of range")
			}
			n.Add(n, new(big.Int).Lsh(big.NewInt(1), 256))
		} else if n.Cmp(limit) >= 0 {
			return nil, errors.New("typed integer out of range")
		}
		n.FillBytes(word)
	}
	return word, nil
}
func TypedHash(raw []byte, version int) ([]byte, error) {
	t, e := parseTyped(raw, version)
	if e != nil {
		return nil, e
	}
	domain, e := t.hashStruct("EIP712Domain", t.Domain, 0)
	if e != nil {
		return nil, e
	}
	b := append([]byte{0x19, 0x01}, domain...)
	if t.Primary != "EIP712Domain" {
		m, e := t.hashStruct(t.Primary, t.Message, 0)
		if e != nil {
			return nil, e
		}
		b = append(b, m...)
	}
	return crypto.Keccak256(b), nil
}

// LegacyHash implements the historical typed-data array format. It is kept
// distinct from EIP-712 v3/v4; the review prominently identifies its limitations.
func LegacyHash(raw []byte) ([]byte, error) {
	v, e := StrictJSON(raw)
	if e != nil {
		return nil, e
	}
	rows, ok := v.([]any)
	if !ok || len(rows) == 0 || len(rows) > 128 {
		return nil, errors.New("legacy typed data requires 1–128 fields")
	}
	schema, values := []byte{}, []byte{}
	for _, r := range rows {
		m, ok := r.(map[string]any)
		if !ok || len(m) != 3 || exact(m, "name", "type", "value") != nil {
			return nil, errors.New("invalid legacy typed field")
		}
		name, _ := m["name"].(string)
		typ, _ := m["type"].(string)
		if len(name) == 0 || len(name) > 256 {
			return nil, errors.New("invalid legacy field name")
		}
		b, e := legacyPack(typ, m["value"], false, 0)
		if e != nil {
			return nil, e
		}
		schema = append(schema, []byte(typ+" "+name)...)
		values = append(values, b...)
	}
	return crypto.Keccak256(crypto.Keccak256(schema), crypto.Keccak256(values)), nil
}
func legacyPack(typ string, v any, array bool, depth int) ([]byte, error) {
	if depth > 8 {
		return nil, errors.New("legacy array depth exceeded")
	}
	base, n, arr, e := splitArray(typ)
	if e != nil {
		return nil, e
	}
	if arr {
		vs, ok := v.([]any)
		if !ok || len(vs) > 2048 || n >= 0 && len(vs) != n {
			return nil, errors.New("invalid legacy array")
		}
		b := []byte{}
		for _, v := range vs {
			x, e := legacyPack(base, v, true, depth+1)
			if e != nil {
				return nil, e
			}
			b = append(b, x...)
		}
		return b, nil
	}
	if typ == "uint" {
		typ = "uint256"
	}
	if typ == "int" {
		typ = "int256"
	}
	kind, size, e := primitiveSize(typ)
	if e != nil {
		return nil, e
	}
	if kind == "string" {
		s, ok := v.(string)
		if !ok {
			return nil, errors.New("invalid legacy string")
		}
		return []byte(s), nil
	}
	if kind == "bytes" && size == 0 {
		return hexBytes(v)
	}
	w, e := primitive(typ, v)
	if e != nil {
		return nil, e
	}
	if array {
		return w, nil
	}
	switch kind {
	case "bytes":
		return w[:size], nil
	case "int", "uint":
		return w[32-size/8:], nil
	case "address":
		return w[12:], nil
	case "bool":
		return w[31:], nil
	}
	return nil, errors.New("unsupported legacy field")
}
