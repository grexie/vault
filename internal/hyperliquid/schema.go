// Package hyperliquid implements a bounded, explicit subset of Hyperliquid's
// signing protocol. It never submits signed actions to the exchange.
package hyperliquid

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/tinylib/msgp/msgp"
)

const MaxInput = 64 * 1024
const maxItems = 50

type member struct {
	name  string
	value any
}
type object []member

func (o object) MarshalJSON() ([]byte, error) {
	b := []byte{'{'}
	for i, m := range o {
		if i > 0 {
			b = append(b, ',')
		}
		k, _ := json.Marshal(m.name)
		v, e := json.Marshal(m.value)
		if e != nil {
			return nil, e
		}
		b = append(b, k...)
		b = append(b, ':')
		b = append(b, v...)
	}
	return append(b, '}'), nil
}
func (o object) get(k string) any {
	for _, m := range o {
		if m.name == k {
			return m.value
		}
	}
	return nil
}
func (o object) str(k string) string { s, _ := o.get(k).(string); return s }

// Reject duplicate (including case-variant) names before encoding/json can
// silently overwrite them. Integers never pass through floating point.
func parse(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxInput || !utf8.Valid(raw) {
		return nil, errors.New("invalid or oversized Hyperliquid JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, e := readValue(d, 0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("expected a JSON object")
	}
	return m, nil
}
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 12 {
		return nil, errors.New("JSON nesting exceeds limit")
	}
	t, e := d.Token()
	if e != nil {
		return nil, errors.New("invalid Hyperliquid JSON")
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
				name, ok := k.(string)
				if !ok || len(name) > 64 || seen[strings.ToLower(name)] || len(m) >= 32 {
					return nil, errors.New("duplicate or invalid JSON field")
				}
				seen[strings.ToLower(name)] = true
				v, e := readValue(d, depth+1)
				if e != nil {
					return nil, e
				}
				m[name] = v
			}
			_, e := d.Token()
			return m, e
		case '[':
			a := []any{}
			for d.More() {
				if len(a) >= maxItems {
					return nil, errors.New("too many action items (maximum 50)")
				}
				v, e := readValue(d, depth+1)
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
	if s, ok := t.(string); ok {
		if len(s) > 512 {
			return nil, errors.New("action string exceeds limit")
		}
		for _, r := range s {
			if r < 32 || r > 126 {
				return nil, errors.New("action strings must use printable ASCII")
			}
		}
	}
	return t, nil
}

type rule func(any) (any, error)
type field struct {
	name     string
	rule     rule
	optional bool
}

func req(n string, r rule) field { return field{n, r, false} }
func opt(n string, r rule) field { return field{n, r, true} }
func fields(fs ...field) rule {
	return func(v any) (any, error) {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("expected object")
		}
		o := object{}
		for _, f := range fs {
			v, exists := m[f.name]
			if !exists {
				if f.optional {
					continue
				}
				return nil, fmt.Errorf("missing %s", f.name)
			}
			value, e := f.rule(v)
			if e != nil {
				return nil, fmt.Errorf("%s: %w", f.name, e)
			}
			o = append(o, member{f.name, value})
		}
		if len(m) != len(o) {
			return nil, errors.New("unknown field in action")
		}
		return o, nil
	}
}
func array(r rule) rule {
	return func(v any) (any, error) {
		a, ok := v.([]any)
		if !ok || len(a) == 0 || len(a) > maxItems {
			return nil, errors.New("expected 1–50 items")
		}
		out := []any{}
		for _, x := range a {
			y, e := r(x)
			if e != nil {
				return nil, e
			}
			out = append(out, y)
		}
		return out, nil
	}
}
func text(v any) (any, error) {
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("expected string")
	}
	return s, nil
}
func boolean(v any) (any, error) {
	b, ok := v.(bool)
	if !ok {
		return nil, errors.New("expected boolean")
	}
	return b, nil
}
func onlyTrue(v any) (any, error) {
	if v != true {
		return nil, errors.New("must be true or omitted")
	}
	return true, nil
}
func unsigned(v any) (any, error) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, errors.New("expected unsigned integer")
	}
	u, e := strconv.ParseUint(string(n), 10, 64)
	if e != nil {
		return nil, errors.New("expected uint64 integer")
	}
	return u, nil
}
func integer(v any) (any, error) {
	n, ok := v.(json.Number)
	if !ok {
		return nil, errors.New("expected signed integer")
	}
	u, e := strconv.ParseInt(string(n), 10, 64)
	if e != nil {
		return nil, errors.New("expected int64 integer")
	}
	return u, nil
}
func bounded(min, max uint64) rule {
	return func(v any) (any, error) {
		n, e := unsigned(v)
		if e != nil {
			return nil, e
		}
		if n.(uint64) < min || n.(uint64) > max {
			return nil, errors.New("integer outside supported range")
		}
		return n, nil
	}
}
func oneOf(values ...string) rule {
	return func(v any) (any, error) {
		for _, s := range values {
			if v == s {
				return s, nil
			}
		}
		return nil, errors.New("unsupported value")
	}
}

var decimalRE = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)

func decimal(v any) (any, error) {
	s, ok := v.(string)
	if !ok || len(s) > 80 || !decimalRE.MatchString(s) {
		return nil, errors.New("expected unsigned plain decimal string")
	}
	return s, nil
}
func positive(v any) (any, error) {
	s, e := decimal(v)
	if e != nil {
		return nil, e
	}
	if strings.Trim(s.(string), "0.") == "" {
		return nil, errors.New("amount must be positive")
	}
	return s, nil
}
func address(v any) (any, error) {
	s, ok := v.(string)
	if !ok || len(s) != 42 || !strings.HasPrefix(s, "0x") || !common.IsHexAddress(s) {
		return nil, errors.New("expected 0x-prefixed address")
	}
	return strings.ToLower(s), nil
}
func subaccount(v any) (any, error) {
	if v == "" {
		return v, nil
	}
	return address(v)
}

var cloidRE = regexp.MustCompile(`^0x[0-9a-fA-F]{32}$`)

func cloid(v any) (any, error) {
	s, ok := v.(string)
	if !ok || !cloidRE.MatchString(s) {
		return nil, errors.New("expected 16-byte client order ID")
	}
	return s, nil
}
func orderID(v any) (any, error) {
	if _, ok := v.(string); ok {
		return cloid(v)
	}
	return unsigned(v)
}
func feeRate(v any) (any, error) {
	s, ok := v.(string)
	if !ok || !strings.HasSuffix(s, "%") {
		return nil, errors.New("fee rate must end in %")
	}
	if _, e := decimal(strings.TrimSuffix(s, "%")); e != nil {
		return nil, e
	}
	return s, nil
}
func grouping(v any) (any, error) {
	if m, ok := v.(map[string]any); ok {
		return fields(req("p", bounded(0, 2147483647)))(m)
	}
	return oneOf("na", "normalTpsl", "positionTpsl")(v)
}
func orderType(v any) (any, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return nil, errors.New("choose one limit or trigger order type")
	}
	if _, ok := m["limit"]; ok {
		return fields(req("limit", fields(req("tif", oneOf("Alo", "Ioc", "Gtc")))))(v)
	}
	return fields(req("trigger", fields(req("isMarket", boolean), req("triggerPx", positive), req("tpsl", oneOf("tp", "sl")))))(v)
}

var orderRule = fields(req("a", bounded(0, 2147483647)), req("b", boolean), req("p", positive), req("s", positive), req("r", boolean), req("t", orderType), opt("c", cloid))
var modifyRule = fields(req("oid", orderID), req("order", orderRule))

// Field order is the SDK wire order, also the MessagePack map order. A caller's
// JSON member order is never allowed to change what is reviewed or signed.
var l1Rules = map[string][]field{
	"order":                {req("orders", array(orderRule)), req("grouping", grouping), opt("builder", fields(req("b", address), req("f", bounded(0, 100000))))},
	"cancel":               {req("cancels", array(fields(req("a", bounded(0, 2147483647)), req("o", unsigned)))), opt("f", onlyTrue)},
	"cancelByCloid":        {req("cancels", array(fields(req("asset", bounded(0, 2147483647)), req("cloid", cloid)))), opt("f", onlyTrue)},
	"modify":               {req("oid", orderID), req("order", orderRule), opt("a", onlyTrue)},
	"batchModify":          {req("modifies", array(modifyRule)), opt("a", onlyTrue)},
	"updateLeverage":       {req("asset", bounded(0, 2147483647)), req("isCross", boolean), req("leverage", bounded(1, 1000))},
	"updateIsolatedMargin": {req("asset", bounded(0, 2147483647)), req("isBuy", onlyTrue), req("ntli", integer)},
	"scheduleCancel":       {opt("time", unsigned)},
	"twapOrder":            {req("twap", fields(req("a", bounded(0, 2147483647)), req("b", boolean), req("s", positive), req("r", boolean), req("m", bounded(5, 1440)), req("t", boolean)))},
	"twapCancel":           {req("a", bounded(0, 2147483647)), req("t", unsigned)},
	"noop":                 {},
}

type typedField struct {
	name, typ string
	rule      rule
}
type userSchema struct {
	name   string
	fields []typedField
}

var userRules = map[string]userSchema{
	"usdSend":            {"UsdSend", []typedField{{"destination", "string", address}, {"amount", "string", positive}, {"time", "uint64", unsigned}}},
	"spotSend":           {"SpotSend", []typedField{{"destination", "string", address}, {"token", "string", text}, {"amount", "string", positive}, {"time", "uint64", unsigned}}},
	"withdraw3":          {"Withdraw", []typedField{{"destination", "string", address}, {"amount", "string", positive}, {"time", "uint64", unsigned}}},
	"usdClassTransfer":   {"UsdClassTransfer", []typedField{{"amount", "string", positive}, {"toPerp", "bool", boolean}, {"nonce", "uint64", unsigned}}},
	"sendAsset":          {"SendAsset", []typedField{{"destination", "string", address}, {"sourceDex", "string", text}, {"destinationDex", "string", text}, {"token", "string", text}, {"amount", "string", positive}, {"fromSubAccount", "string", subaccount}, {"nonce", "uint64", unsigned}}},
	"approveAgent":       {"ApproveAgent", []typedField{{"agentAddress", "address", address}, {"agentName", "string", text}, {"nonce", "uint64", unsigned}}},
	"approveBuilderFee":  {"ApproveBuilderFee", []typedField{{"maxFeeRate", "string", feeRate}, {"builder", "address", address}, {"nonce", "uint64", unsigned}}},
	"tokenDelegate":      {"TokenDelegate", []typedField{{"validator", "address", address}, {"wei", "uint64", unsigned}, {"isUndelegate", "bool", boolean}, {"nonce", "uint64", unsigned}}},
	"userDexAbstraction": {"UserDexAbstraction", []typedField{{"user", "address", address}, {"enabled", "bool", boolean}, {"nonce", "uint64", unsigned}}},
	"userSetAbstraction": {"UserSetAbstraction", []typedField{{"user", "address", address}, {"abstraction", "string", oneOf("disabled", "unifiedAccount", "portfolioMargin")}, {"nonce", "uint64", unsigned}}},
}

func pack(b []byte, v any) []byte {
	switch x := v.(type) {
	case object:
		b = msgp.AppendMapHeader(b, uint32(len(x)))
		for _, m := range x {
			b = msgp.AppendString(b, m.name)
			b = pack(b, m.value)
		}
	case []any:
		b = msgp.AppendArrayHeader(b, uint32(len(x)))
		for _, v := range x {
			b = pack(b, v)
		}
	case string:
		b = msgp.AppendString(b, x)
	case bool:
		b = msgp.AppendBool(b, x)
	case uint64:
		b = msgp.AppendUint64(b, x)
	case int64:
		if x >= 0 {
			b = msgp.AppendUint64(b, uint64(x))
		} else {
			b = msgp.AppendInt64(b, x)
		}
	default:
		panic("unvalidated Hyperliquid value")
	}
	return b
}
