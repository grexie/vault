package identity

import (
	"strings"
	"testing"
)

func TestSecurityReviewEthereumHasOneJSONInterpretation(t *testing.T) {
	base := `{"from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222","chainId":"0x1","nonce":"0x0","gas":"0x5208","gasPrice":"0x1","value":"0x0","data":"0x"}`
	if _, err := ReviewEthereum([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{
		`,"Data":"0xdeadbeef"`,
		`,"data":"0xdeadbeef"`,
		`,"To":"0x3333333333333333333333333333333333333333"`,
		`,"to":"0x3333333333333333333333333333333333333333"`,
		`,"ChainId":"0x2"`,
		`,"chainId":"0x2"`,
		`,"\u0064ata":"0xdeadbeef"`,
	} {
		raw := strings.TrimSuffix(base, "}") + suffix + "}"
		if _, err := DecodeEthereum([]byte(raw)); err == nil {
			t.Fatalf("accepted conflicting JSON members: %s", suffix)
		}
	}
	disagree := strings.TrimSuffix(base, "}") + `,"input":"0xdeadbeef"}`
	if _, err := ReviewEthereum([]byte(disagree)); err == nil {
		t.Fatal("accepted different input/data bytes")
	}
}
