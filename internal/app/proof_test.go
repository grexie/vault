package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/http"
	"testing"

	"github.com/grexie/vault/internal/proof"
)

func TestCopiedCapabilityAndReplayedProofCannotSign(t *testing.T) {
	h := newHarness(t)
	l := h.request("machine-bound", 60)
	h.approve(l)
	path := h.origin + "/v1/requests/" + l.Request.ID + "/agent"
	body := []byte(`{"action":"list"}`)
	request := func() *http.Request {
		r, _ := http.NewRequest("POST", path, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+l.Capability)
		return r
	}
	check := func(r *http.Request, want int) {
		t.Helper()
		res, e := h.http.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, res.Body)
		res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("got %d want %d", res.StatusCode, want)
		}
	}
	check(request(), 401)
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	r := request()
	proof.Sign(r, body, foreign)
	check(r, 401)
	r = request()
	proof.Sign(r, body, h.requestKeys[l.Request.ID])
	headers := r.Header.Clone()
	check(r, 200)
	r = request()
	r.Header = headers
	check(r, 401) // replay
	r = request()
	proof.Sign(r, body, h.requestKeys[l.Request.ID])
	r.Body = io.NopCloser(bytes.NewReader([]byte(`{"action":"sign"}`)))
	r.ContentLength = int64(len(`{"action":"sign"}`))
	check(r, 401)
	h.sign(l, 200)
}
