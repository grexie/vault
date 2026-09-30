package vaultwire

import "testing"

func TestSecurityReviewRequestCannotChangeSecretClass(t *testing.T) {
	cases := []struct {
		name string
		q    Request
		want bool
	}{
		{"managed SSH", Request{Kind: "ssh", IdentityType: "ssh", Managed: true}, true},
		{"unmanaged SSH", Request{Kind: "ssh", IdentityType: "ssh"}, false},
		{"age SSH", Request{Kind: "age", IdentityType: "ssh", Managed: true}, true},
		{"unmanaged age", Request{Kind: "age", IdentityType: "ssh"}, false},
		{"Ethereum cannot export SSH", Request{Kind: "ethereum", IdentityType: "ssh", Managed: true}, false},
		{"Ethereum cannot export a password", Request{Kind: "ethereum", IdentityType: "login", Managed: true}, false},
		{"Bitcoin cannot export a card", Request{Kind: "bitcoin", IdentityType: "payment-card", Managed: true}, false},
		{"unmanaged Ethereum", Request{Kind: "ethereum", IdentityType: "ethereum"}, false},
		{"unmanaged Bitcoin", Request{Kind: "bitcoin", IdentityType: "bitcoin"}, false},
		{"managed Ethereum", Request{Kind: "ethereum", IdentityType: "ethereum", Managed: true}, true},
		{"managed Bitcoin", Request{Kind: "bitcoin", IdentityType: "bitcoin", Managed: true}, true},
		{"GitHub command", Request{Kind: "credentials", IdentityType: "github", Payload: []byte(`{"provider":"github","mode":"command"}`)}, true},
		{"GitHub review cannot export AWS", Request{Kind: "credentials", IdentityType: "aws", Payload: []byte(`{"provider":"github","mode":"command"}`)}, false},
		{"custom provider namespace", Request{Kind: "api", IdentityType: "credentials", Network: "example", Payload: []byte(`{"provider":"example"}`)}, true},
		{"custom namespace mismatch", Request{Kind: "api", IdentityType: "credentials", Network: "other", Payload: []byte(`{"provider":"example"}`)}, false},
		{"autofill cannot export key", Request{Kind: "autofill", IdentityType: "ssh", Payload: []byte(`{"provider":"login"}`)}, false},
		{"autofill cannot substitute card", Request{Kind: "autofill", IdentityType: "payment-card", Payload: []byte(`{"provider":"login"}`)}, false},
		{"website import cannot read SSH", Request{Kind: "keychain-import", IdentityType: "ssh"}, false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidateRequest(tt.q) == nil; got != tt.want {
				t.Fatalf("accepted=%v, want=%v", got, tt.want)
			}
		})
	}
}
