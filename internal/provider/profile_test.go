package provider

import (
	"net/http"
	"strings"
	"testing"
)

func TestProfileBoundaries(t *testing.T) {
	for name, p := range Builtins() {
		if e := p.Validate(); e != nil {
			t.Fatalf("%s: %v", name, e)
		}
	}
	p := Profile{Version: 1, Name: "example", Label: "Example", Fields: []Field{{Name: "username", Label: "Username", Required: true}, {Name: "password", Label: "Password", Secret: true, Required: true}}, CLI: &CLI{Executable: "example", Env: map[string]string{"EXAMPLE_USER": "username", "EXAMPLE_PASSWORD": "password"}}, HTTP: &HTTP{Origin: "https://api.example.com", PathPrefix: "/v1/", Methods: []string{"GET"}, Auth: Auth{Method: "basic", Username: "username", Password: "password"}}}
	c := Credentials{Provider: "example", Fields: map[string]string{"username": "fixture", "password": "fixture-secret"}}
	for _, url := range []string{"https://api.example.com.evil.test/v1/me", "http://api.example.com/v1/me", "https://api.example.com/v2/me", "https://api.example.com/v1/%2e%2e/secrets", "https://api.example.com/v1/../secrets"} {
		r, _ := http.NewRequest("GET", url, nil)
		if p.Authorize(r, c) == nil {
			t.Fatal("allowed escaped destination", url)
		}
	}
	r, _ := http.NewRequest("GET", "https://api.example.com/v1/me", nil)
	r.Header.Set("Cookie", "not-allowed")
	if e := p.Authorize(r, c); e != nil {
		t.Fatal(e)
	}
	u, password, ok := r.BasicAuth()
	if !ok || u != "fixture" || password != "fixture-secret" || r.Header.Get("Cookie") != "" {
		t.Fatal("incorrect basic auth")
	}
	r.Method = "POST"
	if p.Authorize(r, c) == nil {
		t.Fatal("allowed prohibited method")
	}
	for _, env := range []string{"LD_PRELOAD", "PATH", "HOME", "NODE_OPTIONS", "DYLD_INSERT_LIBRARIES", "VAULT_TOKEN"} {
		p.CLI.Env = map[string]string{env: "password"}
		if p.Validate() == nil {
			t.Fatal("allowed unsafe environment", env)
		}
	}
}
func TestCredentialValidationDoesNotExposeValues(t *testing.T) {
	secret := "fixture-secret\r\nInjected: value"
	_, e := DecodeCredentials([]byte(`{"provider":"github","fields":{"token":"fixture-secret\r\nInjected: value"}}`))
	if e == nil || strings.Contains(e.Error(), secret) {
		t.Fatal("invalid value exposed or accepted")
	}
	if _, e = DecodeCredentials([]byte(`{"provider":"payment-card","fields":{"cardholder":"Fixture","number":"4242424242424242","expiryMonth":"12","expiryYear":"2030","cvv":"123"}}`)); e == nil {
		t.Fatal("CVV admitted to cloud credential")
	}
	if _, e = DecodeCredentials([]byte(`{"provider":"payment-card","fields":{"cardholder":"Fixture","number":"4242424242424242","expiryMonth":"12","expiryYear":"2030"}}`)); e != nil {
		t.Fatal(e)
	}
}
