package identity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

type DecodedCall struct {
	Method    string        `json:"method"`
	Arguments []Field       `json:"arguments"`
	Children  []DecodedCall `json:"children,omitempty"`
	Warning   string        `json:"warning,omitempty"`
}

// DecodeABI accepts a browser-fetched ABI as data, never executable code. It
// handles tuples/arrays, rejects selector ambiguity and checks the encoding
// round-trip so ignored trailing bytes cannot hide a different call.
func DecodeABI(abiJSON []byte, calldata []byte) (DecodedCall, error) {
	if len(abiJSON) > 2*1024*1024 || len(calldata) > 128*1024 || len(calldata) < 4 {
		return DecodedCall{}, errors.New("invalid ABI or calldata size")
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(abiJSON, &entries) != nil || len(entries) > 4000 {
		return DecodedCall{}, errors.New("invalid contract ABI")
	}
	parsed, err := abi.JSON(bytes.NewReader(abiJSON))
	if err != nil {
		return DecodedCall{}, errors.New("invalid contract ABI")
	}
	return decodeCall(parsed, calldata, 0)
}
func decodeCall(parsed abi.ABI, data []byte, depth int) (DecodedCall, error) {
	var matched *abi.Method
	for _, method := range parsed.Methods {
		if bytes.Equal(method.ID, data[:4]) {
			if matched != nil && matched.Sig != method.Sig {
				return DecodedCall{}, errors.New("ambiguous function selector")
			}
			copy := method
			matched = &copy
		}
	}
	if matched == nil {
		return DecodedCall{}, errors.New("method is not present in the verified ABI")
	}
	values, err := matched.Inputs.Unpack(data[4:])
	if err != nil {
		return DecodedCall{}, errors.New("calldata does not match the method ABI")
	}
	encoded, err := matched.Inputs.Pack(values...)
	if err != nil || !bytes.Equal(encoded, data[4:]) {
		return DecodedCall{}, errors.New("noncanonical or trailing calldata")
	}
	out := DecodedCall{Method: matched.Sig, Arguments: []Field{}}
	for i, v := range values {
		name := matched.Inputs[i].Name
		if name == "" {
			name = fmt.Sprintf("Argument %d", i+1)
		}
		out.Arguments = append(out.Arguments, Field{name + " (" + matched.Inputs[i].Type.String() + ")", formatABI(v, 0)})
	}
	if depth < 3 && (matched.Sig == "multicall(bytes[])" || matched.Sig == "multicall(uint256,bytes[])") {
		index := 0
		if len(values) == 2 {
			index = 1
		}
		calls, ok := values[index].([][]byte)
		if ok && len(calls) <= 50 {
			for _, call := range calls {
				if len(call) < 4 {
					out.Children = append(out.Children, DecodedCall{Method: "Unknown call", Warning: "Short calldata"})
					continue
				}
				child, e := decodeCall(parsed, call, depth+1)
				if e != nil {
					child = DecodedCall{Method: "Unknown call", Warning: "Nested calldata: 0x" + hex.EncodeToString(call)}
				}
				out.Children = append(out.Children, child)
			}
		} else {
			out.Warning = "Nested call count exceeds the decoding limit"
		}
	}
	return out, nil
}
func formatABI(value any, depth int) string {
	if depth > 8 {
		return "[nested value exceeds display limit]"
	}
	switch v := value.(type) {
	case *big.Int:
		return v.String()
	case common.Address:
		return v.Hex()
	case []byte:
		return "0x" + hex.EncodeToString(v)
	case string:
		return fmt.Sprintf("%q", v)
	case bool:
		return fmt.Sprint(v)
	}
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Array || v.Kind() == reflect.Slice {
		if v.Type().Elem().Kind() == reflect.Uint8 {
			b := make([]byte, v.Len())
			for i := range b {
				b[i] = byte(v.Index(i).Uint())
			}
			return "0x" + hex.EncodeToString(b)
		}
		parts := []string{}
		for i := 0; i < v.Len(); i++ {
			if i == 200 {
				parts = append(parts, "... inspect raw calldata for remaining values")
				break
			}
			parts = append(parts, formatABI(v.Index(i).Interface(), depth+1))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	if v.Kind() == reflect.Struct {
		parts := []string{}
		for i := 0; i < v.NumField(); i++ {
			parts = append(parts, v.Type().Field(i).Name+": "+formatABI(v.Field(i).Interface(), depth+1))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return fmt.Sprint(value)
}
