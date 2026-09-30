package cloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/vaultwire"
)

func securityReviewProxyServer(t *testing.T, cidrs ...string) *Server {
	t.Helper()
	store, err := cloudstore.New(cloudstore.NewMemory(), random(32))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(context.Background(), Config{Origin: "https://vault.example", TrustedProxyCIDRs: cidrs}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSecurityReviewProxyIdentityBoundary(t *testing.T) {
	proxies, err := trustedProxies([]string{"10.20.0.4/32", "2001:db8::7/128"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{proxies: proxies}
	for _, test := range []struct {
		name, peer string
		header     []string
		want       string
	}{
		{"untrusted ignores forged header", "192.0.2.7:40000", []string{"198.51.100.9"}, "192.0.2.7"},
		{"untrusted ignores malformed header", "192.0.2.7:40000", []string{"invalid", "also invalid"}, "192.0.2.7"},
		{"loopback is not implicitly trusted", "127.0.0.1:40000", []string{"198.51.100.9"}, "127.0.0.1"},
		{"valid IPv4", "10.20.0.4:40000", []string{"198.51.100.9"}, "198.51.100.9"},
		{"mapped IPv4 peer", "[::ffff:10.20.0.4]:40000", []string{"198.51.100.9"}, "198.51.100.9"},
		{"mapped IPv4 client", "10.20.0.4:40000", []string{"::ffff:198.51.100.9"}, "198.51.100.9"},
		{"valid IPv6", "[2001:db8::7]:40000", []string{"2001:0db8:0:0::9"}, "2001:db8::9"},
		{"trusted missing header", "10.20.0.4:40000", nil, ""},
		{"trusted empty header", "10.20.0.4:40000", []string{""}, ""},
		{"trusted duplicate header", "10.20.0.4:40000", []string{"198.51.100.9", "198.51.100.9"}, ""},
		{"trusted comma list", "10.20.0.4:40000", []string{"198.51.100.9, 192.0.2.7"}, ""},
		{"trusted IPv4 port", "10.20.0.4:40000", []string{"198.51.100.9:40000"}, ""},
		{"trusted IPv6 port", "10.20.0.4:40000", []string{"[2001:db8::9]:40000"}, ""},
		{"trusted IPv6 zone", "10.20.0.4:40000", []string{"fe80::9%en0"}, ""},
		{"trusted hostname", "10.20.0.4:40000", []string{"client.example"}, ""},
		{"trusted quoted literal", "10.20.0.4:40000", []string{`"198.51.100.9"`}, ""},
		{"trusted leading whitespace", "10.20.0.4:40000", []string{" 198.51.100.9"}, ""},
		{"trusted trailing whitespace", "10.20.0.4:40000", []string{"198.51.100.9 "}, ""},
		{"invalid TCP peer", "not-an-address", []string{"198.51.100.9"}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://vault.example/api/v1/auth/login/begin", nil)
			r.RemoteAddr = test.peer
			for _, value := range test.header {
				r.Header.Add("X-Real-IP", value)
			}
			r.Header.Set("X-Forwarded-For", "203.0.113.99, 203.0.113.98")
			r.Header.Set("Forwarded", "for=203.0.113.97")
			got, err := s.clientIP(r)
			if test.want == "" {
				if err == nil {
					t.Fatalf("ambiguous address accepted as %q", got)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("client = %q, error = %v; want %q", got, err, test.want)
			}
		})
	}
	noTrust := &Server{}
	r := httptest.NewRequest(http.MethodPost, "https://vault.example/", nil)
	r.RemoteAddr = "10.20.0.4:40000"
	r.Header.Set("X-Real-IP", "198.51.100.9")
	if got, err := noTrust.clientIP(r); err != nil || got != "10.20.0.4" {
		t.Fatal("empty proxy configuration trusted a forwarded header", got, err)
	}
}

func TestSecurityReviewProxyConfigurationRejectsUnsafeInput(t *testing.T) {
	for _, cidr := range []string{"", " ", "0.0.0.0/0", "::/0", "::ffff:0:0/96", "::ffff:10.20.0.4/95", "10.20.0.4", "10.20.0.4/33", "proxy.example/32", "fe80::1%en0/128"} {
		t.Run(cidr, func(t *testing.T) {
			store, err := cloudstore.New(cloudstore.NewMemory(), random(32))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = New(context.Background(), Config{Origin: "https://vault.example", TrustedProxyCIDRs: []string{cidr}}, store, nil); err == nil {
				t.Fatalf("invalid proxy configuration reached startup: %q", cidr)
			}
		})
	}
	proxies, err := trustedProxies([]string{" 10.20.0.4/32 ", "::ffff:10.20.0.5/128", "2001:db8::7/128"})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"10.20.0.4/32", "10.20.0.5/32", "2001:db8::7/128"} {
		if proxies[i].String() != want {
			t.Errorf("proxy %d = %s, want %s", i, proxies[i], want)
		}
	}
}

func securityReviewLogin(s *Server, peer string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://vault.example/api/v1/auth/login/begin", bytes.NewBufferString(`{}`))
	r.RemoteAddr = peer
	r.Header = headers.Clone()
	r.Header.Set("Origin", "https://vault.example")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestSecurityReviewProxyAuthQuotasAreClientBound(t *testing.T) {
	s := securityReviewProxyServer(t, "10.20.0.4/32")
	for i := 0; i < 30; i++ {
		w := securityReviewLogin(s, fmt.Sprintf("10.20.0.4:%d", 40000+i), http.Header{"X-Real-Ip": {"198.51.100.9"}})
		if w.Code != http.StatusOK {
			t.Fatalf("client request %d failed early: %d %s", i, w.Code, w.Body.String())
		}
	}
	if w := securityReviewLogin(s, "10.20.0.4:45000", http.Header{"X-Real-Ip": {"::ffff:198.51.100.9"}}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("changing port or address spelling bypassed quota: %d", w.Code)
	}
	if w := securityReviewLogin(s, "10.20.0.4:45000", http.Header{"X-Real-Ip": {"198.51.100.10"}}); w.Code != http.StatusOK {
		t.Fatalf("one proxied client blocked another: %d %s", w.Code, w.Body.String())
	}
	if w := securityReviewLogin(s, "10.20.0.4:45000", http.Header{"X-Real-Ip": {"198.51.100.11", "198.51.100.12"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("ambiguous proxy identity reached authentication: %d", w.Code)
	}
}

func TestSecurityReviewUntrustedProxyHeadersCannotResetQuota(t *testing.T) {
	s := securityReviewProxyServer(t, "10.20.0.4/32")
	for i := 0; i < 31; i++ {
		fake := fmt.Sprintf("198.51.100.%d", i+1)
		w := securityReviewLogin(s, fmt.Sprintf("192.0.2.7:%d", 40000+i), http.Header{"X-Real-Ip": {fake}, "X-Forwarded-For": {fake}, "Forwarded": {"for=" + fake}})
		want := http.StatusOK
		if i == 30 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("spoofed header request %d returned %d, want %d", i, w.Code, want)
		}
	}
}

func TestSecurityReviewCrossSiteGETCannotConsumeAuthQuota(t *testing.T) {
	s := securityReviewProxyServer(t, "10.20.0.4/32")
	// An arbitrary website can cause GETs from the victim's browser, for example
	// through image elements. These unsupported requests must not consume the
	// quota for same-origin POST passkey ceremonies.
	for i := 0; i < 30; i++ {
		r := httptest.NewRequest(http.MethodGet, "https://vault.example/api/v1/auth/login/begin", nil)
		r.RemoteAddr = "10.20.0.4:40000"
		r.Header.Set("X-Real-IP", "198.51.100.9")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed && w.Code != http.StatusForbidden {
			t.Fatalf("unsupported cross-site GET returned %d", w.Code)
		}
	}
	if w := securityReviewLogin(s, "10.20.0.4:40000", http.Header{"X-Real-Ip": {"198.51.100.9"}}); w.Code != http.StatusOK {
		t.Fatalf("cross-site GETs exhausted the victim's authentication quota: %d %s", w.Code, w.Body.String())
	}
}

func TestSecurityReviewEnrollmentQuotaIsSeparateAndPrecedesReplayWrites(t *testing.T) {
	s := securityReviewProxyServer(t, "10.20.0.4/32")
	ctx := context.Background()
	for i := 0; i < 30; i++ {
		if w := securityReviewLogin(s, "10.20.0.4:40000", http.Header{"X-Real-Ip": {"198.51.100.9"}}); w.Code != http.StatusOK {
			t.Fatal("fixture login request failed", w.Code)
		}
	}
	for i := 0; i < 31; i++ {
		cfg, err := device.NewConfig("https://vault.example", "Disposable proxy fixture")
		if err != nil {
			t.Fatal(err)
		}
		body, err := json.Marshal(vaultwire.Enrollment{Device: cfg.Device, PairingHash: vaultwire.Digest(cfg.PairingSecret)})
		if err != nil {
			t.Fatal(err)
		}
		path := "/api/v1/device/enroll"
		nonce := device.RandomID()
		proof, err := vaultwire.Sign(cfg.PrivateKey, "http", vaultwire.HTTPProof{DeviceID: cfg.Device.ID, Method: http.MethodPost, Path: path, BodyHash: vaultwire.Digest(body), Nonce: nonce, At: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(proof)
		r := httptest.NewRequest(http.MethodPost, "https://vault.example"+path, bytes.NewReader(body))
		r.RemoteAddr = "10.20.0.4:40000"
		r.Header.Set("X-Real-IP", "198.51.100.9")
		r.Header.Set("X-Vault-Proof", base64.RawURLEncoding.EncodeToString(encoded))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		want := http.StatusCreated
		if i == 30 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("enrollment %d returned %d, want %d: %s", i, w.Code, want, w.Body.String())
		}
		if i == 30 {
			if _, err = s.store.Get(ctx, "replays", cfg.Device.ID+":"+nonce, new(bool)); err != cloudstore.ErrNotFound {
				t.Fatalf("rejected enrollment wrote a replay record: %v", err)
			}
			if _, err = s.store.Get(ctx, "devices", cfg.Device.ID, new(deviceRecord)); err != cloudstore.ErrNotFound {
				t.Fatalf("rejected enrollment wrote a device record: %v", err)
			}
		}
	}
}

func TestSecurityReviewRateKeyCapacityIsBounded(t *testing.T) {
	s := &Server{rates: map[string]rate{}}
	for i := 0; i < maxRateKeys; i++ {
		if !s.allowKey(fmt.Sprintf("capacity-fixture/%d", i)) {
			t.Fatalf("valid key %d rejected before capacity", i)
		}
	}
	if s.allowKey("overflow-fixture") || len(s.rates) != maxRateKeys {
		t.Fatal("new rate key exceeded the memory bound")
	}
	if _, exists := s.rates["overflow-fixture"]; exists {
		t.Fatal("rejected rate key was allocated")
	}
	if !s.allowKey("capacity-fixture/0") {
		t.Fatal("capacity exhaustion blocked an existing client's remaining allowance")
	}
	s.rates["capacity-fixture/1"] = rate{Start: time.Now().Add(-2 * time.Minute), N: 30}
	if !s.allowKey("replacement-fixture") || len(s.rates) != maxRateKeys {
		t.Fatal("expired rate keys were not reclaimed")
	}
}
