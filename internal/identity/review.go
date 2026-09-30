package identity

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type Field struct {
	Label string `json:"label"`
	Value string `json:"value"`
}
type Review struct {
	Kind     string   `json:"kind"`
	Title    string   `json:"title"`
	Fields   []Field  `json:"fields"`
	Warnings []string `json:"warnings"`
	Raw      string   `json:"raw"`
	Digest   string   `json:"digest"`
}

// ReviewEthereum decodes the exact transaction passed to SignEthereum. Display
// strings from the requester are not used as evidence of transaction semantics.
func ReviewEthereum(raw []byte) (Review, error) {
	a, err := DecodeEthereum(raw)
	if err != nil {
		return Review{}, err
	}
	tx, err := a.Transaction()
	if err != nil {
		return Review{}, err
	}
	r := Review{Kind: "ethereum", Title: "Send Ethereum transaction", Fields: []Field{}, Warnings: []string{}}
	chain := (*big.Int)(a.ChainID)
	value := tx.Value()
	r.Fields = append(r.Fields, Field{"Network", fmt.Sprintf("Chain %s", chain)}, Field{"From", a.From.Hex()}, Field{"Nonce", fmt.Sprint(tx.Nonce())}, Field{"Amount", formatUnits(value, 18) + " ETH (" + value.String() + " wei)"})
	if a.To == nil {
		r.Title = "Deploy a contract"
		r.Fields = append(r.Fields, Field{"To", "New contract"})
		r.Warnings = append(r.Warnings, "Contract creation executes the supplied bytecode. Review the code before approving.")
	} else {
		r.Fields = append(r.Fields, Field{"To", a.To.Hex()})
	}
	maxFee := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap())
	r.Fields = append(r.Fields, Field{"Gas limit", fmt.Sprint(tx.Gas())}, Field{"Maximum network fee", formatUnits(maxFee, 18) + " ETH"}, Field{"Maximum total spend", formatUnits(new(big.Int).Add(value, maxFee), 18) + " ETH"})
	data := tx.Data()
	r.Raw = "0x" + hex.EncodeToString(data)
	if a.To != nil && len(data) == 0 {
		r.Title = "Send ETH"
	}
	if a.To != nil && len(data) > 0 {
		r.Title = "Call a contract"
		if len(data) < 4 {
			r.Warnings = append(r.Warnings, "Short calldata: contract fallback behavior is unknown.")
		} else {
			selector := hex.EncodeToString(data[:4])
			r.Fields = append(r.Fields, Field{"Function selector", "0x" + selector})
			signature, fields, warnings, ok := decodeKnownCall(selector, data[4:])
			if ok {
				r.Title = signature
				r.Fields = append(r.Fields, fields...)
				r.Warnings = append(r.Warnings, warnings...)
				r.Warnings = append(r.Warnings, "Decoded from a standard function selector. Token decimals, contract implementation and execution outcome are not verified.")
			} else {
				r.Warnings = append(r.Warnings, "Unrecognized or malformed contract call. Its effects cannot be determined from the available ABI; inspect the complete calldata.")
			}
		}
	}
	// The digest commits to the full canonical transaction, including chain ID.
	r.Digest = ethereumDigest(a, tx)
	return r, nil
}
func formatUnits(n *big.Int, decimals int) string {
	s := n.String()
	for len(s) <= decimals {
		s = "0" + s
	}
	if decimals == 0 {
		return s
	}
	whole, frac := s[:len(s)-decimals], s[len(s)-decimals:]
	for len(frac) > 0 && frac[len(frac)-1] == '0' {
		frac = frac[:len(frac)-1]
	}
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}
func decodeKnownCall(selector string, data []byte) (string, []Field, []string, bool) {
	specs := map[string]struct {
		name string
		args []string
	}{
		"a9059cbb": {"transfer(address,uint256)", []string{"Recipient:address", "Token amount (base units):uint"}},
		"095ea7b3": {"approve(address,uint256)", []string{"Spender:address", "Allowance (base units or token ID):uint"}},
		"23b872dd": {"transferFrom(address,address,uint256)", []string{"From:address", "Recipient:address", "Amount (base units) or NFT token ID:uint"}},
		"a22cb465": {"setApprovalForAll(address,bool)", []string{"Operator:address", "All assets approved:bool"}},
		"42842e0e": {"safeTransferFrom(address,address,uint256)", []string{"From:address", "Recipient:address", "NFT token ID:uint"}},
	}
	spec, ok := specs[selector]
	if !ok || len(data) != len(spec.args)*32 {
		return "", nil, nil, false
	}
	fields := []Field{}
	warnings := []string{}
	for i, arg := range spec.args {
		split := len(arg) - 1
		for split >= 0 && arg[split] != ':' {
			split--
		}
		label, typ := arg[:split], arg[split+1:]
		word := data[i*32 : (i+1)*32]
		n := new(big.Int).SetBytes(word)
		v := n.String()
		switch typ {
		case "address":
			if new(big.Int).SetBytes(word[:12]).Sign() != 0 {
				return "", nil, nil, false
			}
			v = common.BytesToAddress(word[12:]).Hex()
		case "bool":
			if n.Cmp(big.NewInt(1)) > 0 {
				return "", nil, nil, false
			}
			v = "No"
			if n.Sign() != 0 {
				v = "Yes"
				warnings = append(warnings, "This operator will be authorized to transfer every asset covered by this contract.")
			}
		}
		fields = append(fields, Field{label, v})
		if selector == "095ea7b3" && i == 1 {
			max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
			if n.Cmp(max) == 0 {
				warnings = append(warnings, "UNLIMITED allowance: the spender can use the full token balance, including future deposits.")
			} else if n.Sign() != 0 {
				warnings = append(warnings, "An approval grants spending authority; it does not transfer tokens immediately.")
			}
		}
	}
	return spec.name, fields, warnings, true
}
