package app

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/grexie/vault/internal/signer"
	"golang.org/x/crypto/ssh"
)

func ageFixture(t *testing.T, h *harness) ([]byte, []byte) {
	k, _ := ssh.NewSignerFromKey(h.key)
	r, e := agessh.ParseRecipient(string(ssh.MarshalAuthorizedKey(k.PublicKey())))
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	w, e := age.Encrypt(&b, r)
	if e != nil {
		t.Fatal(e)
	}
	w.Write([]byte("synthetic document"))
	if e = w.Close(); e != nil {
		t.Fatal(e)
	}
	header, e := age.ExtractHeader(bytes.NewReader(b.Bytes()))
	if e != nil {
		t.Fatal(e)
	}
	return b.Bytes(), header
}

func TestAgeScopesAndOneShot(t *testing.T) {
	h := newHarness(t)
	document, header := ageFixture(t, h)
	sshOnly := h.request("ssh-only", 30)
	h.approve(sshOnly)
	h.call("POST", "/v1/requests/"+sshOnly.Request.ID+"/age", sshOnly.Capability, map[string]any{"header": header}, nil, 403)
	h.call("GET", "/v1/recipient", "wrong", nil, nil, 401)
	var recipient map[string]string
	h.call("GET", "/v1/recipient", h.token, nil, &recipient, 200)
	if recipient["fingerprint"] != h.fingerprint {
		t.Fatal("incorrect recipient")
	}
	for _, scope := range []string{"age", "ssh,age"} {
		var l lease
		h.call("POST", "/v1/requests", h.token, map[string]any{"session": "docs-" + scope[:3], "reason": "Read synthetic test documents", "access": scope, "socket": "/tmp/docs.sock", "durationSeconds": 60}, &l, 201)
		path := "/v1/requests/" + l.Request.ID + "/age"
		h.call("POST", path, l.Capability, map[string]any{"header": header}, nil, 403)
		h.approve(l)
		want := 403
		if scope == "ssh,age" {
			want = 200
		}
		h.sign(l, want)
		h.call("POST", path, l.Capability, map[string]any{"header": []byte("invalid")}, nil, 400)
		var reply signer.Reply
		h.call("POST", path, l.Capability, map[string]any{"header": header}, &reply, 200)
		r, e := age.Decrypt(bytes.NewReader(document), age.NewInjectedFileKeyIdentity(reply.FileKey))
		if e != nil {
			t.Fatal(e)
		}
		plain, e := io.ReadAll(r)
		if e != nil || string(plain) != "synthetic document" {
			t.Fatal("document decryption failed")
		}
		h.call("POST", path, sshOnly.Capability, map[string]any{"header": header}, nil, 401)
		h.call("POST", "/v1/requests/"+l.Request.ID+"/revoke", l.Capability, map[string]any{}, nil, 200)
		h.call("POST", path, l.Capability, map[string]any{"header": header}, nil, 403)
	}
	digest := sha256.Sum256(header)
	var once lease
	h.call("POST", "/v1/requests", h.token, map[string]any{"session": "single-document", "reason": "Read one synthetic document", "mode": "age-once", "access": "age", "headerHash": url64(digest[:])}, &once, 201)
	if once.Request.Socket != "" || once.Request.DurationSeconds != 0 {
		t.Fatal("one shot created a lease")
	}
	h.approve(once)
	path := "/v1/requests/" + once.Request.ID + "/age"
	h.call("POST", path, once.Capability, map[string]any{"header": []byte("different document")}, nil, 403)
	h.call("POST", path, once.Capability, map[string]any{"header": header}, nil, 200)
	h.call("POST", path, once.Capability, map[string]any{"header": header}, nil, 403)
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if h.s.state.Requests[once.Request.ID].Status != "completed" || h.s.live[once.Request.ID].Worker != nil {
		t.Fatal("one-shot worker was not reaped")
	}
}

func TestPublicRecipientHasNoUnlockSideEffects(t *testing.T) {
	h := newHarness(t)
	h.call("GET", "/v1/recipient", h.token, nil, nil, 409) // legacy record learns its public key on approval
	l := h.request("publish-public", 30)
	h.approve(l)
	h.call("POST", "/v1/requests/"+l.Request.ID+"/revoke", l.Capability, map[string]any{}, nil, 200)
	h.call("GET", "/v1/recipient", h.token, nil, nil, 200)
	h.s.mu.Lock()
	defer h.s.mu.Unlock()
	if len(h.s.state.Requests) != 1 || h.s.live[l.Request.ID].Worker != nil {
		t.Fatal("public metadata request opened a grant")
	}
}
