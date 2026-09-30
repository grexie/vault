//go:build unix

package browserwallet

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/grexie/vault/internal/vaultwire"
)

func nativeSecurityFrame(raw []byte) []byte {
	frame := make([]byte, 4+len(raw))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(raw)))
	copy(frame[4:], raw)
	return frame
}

func nativeSecurityRequest(id, origin, method string, params any) []byte {
	raw, e := json.Marshal(map[string]any{"id": id, "origin": origin, "method": method, "params": params})
	if e != nil {
		panic(e)
	}
	return raw
}

func nativeSecurityRead(r io.Reader) (NativeResponse, error) {
	var header [4]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return NativeResponse{}, e
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || n > 1024*1024 {
		return NativeResponse{}, fmt.Errorf("invalid response frame size: %d", n)
	}
	raw := make([]byte, n)
	if _, e := io.ReadFull(r, raw); e != nil {
		return NativeResponse{}, e
	}
	var response NativeResponse
	e := json.Unmarshal(raw, &response)
	return response, e
}

func nativeSecurityMalformedMessages() map[string][]byte {
	badParams := func(params string) []byte {
		return []byte(`{"id":"bad","origin":"https://malicious.example","method":"eth_requestAccounts","params":` + params + `}`)
	}
	return map[string][]byte{
		"complete malformed JSON": []byte(`{`),
		"trailing value":          []byte(`{"id":"bad"} {}`),
		"nonobject":               []byte(`[]`),
		"null envelope":           []byte(`null`),
		"invalid UTF-8":           append([]byte(`{"id":"bad","params":"`), 0xff),
		"duplicate envelope id":   []byte(`{"id":"bad","id":"other","origin":"https://malicious.example","method":"eth_requestAccounts","params":[]}`),
		"alias envelope id":       []byte(`{"id":"bad","ID":"other","origin":"https://malicious.example","method":"eth_requestAccounts","params":[]}`),
		"noncanonical method":     []byte(`{"id":"bad","origin":"https://malicious.example","Method":"eth_requestAccounts","params":[]}`),
		"unknown envelope field":  []byte(`{"id":"bad","origin":"https://malicious.example","method":"eth_requestAccounts","params":[],"extra":true}`),
		"nonstring method":        []byte(`{"id":"bad","origin":"https://malicious.example","method":42,"params":[]}`),
		"null method":             []byte(`{"id":"bad","origin":"https://malicious.example","method":null,"params":[]}`),
		"empty method":            nativeSecurityRequest("bad", "https://malicious.example", "", []any{}),
		"Unicode method":          nativeSecurityRequest("bad", "https://malicious.example", "eth_"+strings.Repeat("🔒", 30), []any{}),
		"ASCII oversized method":  nativeSecurityRequest("bad", "https://malicious.example", "eth_"+strings.Repeat("x", 80), []any{}),
		"method control byte":     nativeSecurityRequest("bad", "https://malicious.example", "eth_chainId\n", []any{}),
		"oversized origin":        nativeSecurityRequest("bad", "https://"+strings.Repeat("a", 512)+".example", "eth_requestAccounts", []any{}),
		"nonarray params":         badParams(`{}`),
		"duplicate params":        badParams(`[{"value":1,"value":2}]`),
		"alias params":            badParams(`[{"value":1,"Value":2}]`),
		"excessive params depth":  badParams(strings.Repeat("[", 40) + "0" + strings.Repeat("]", 40)),
		"excessive params nodes":  badParams(`[` + strings.Repeat(`0,`, 10001) + `0]`),
		"cancel with request":     []byte(`{"id":"bad","cancel":"pending","origin":"https://malicious.example","method":"eth_requestAccounts","params":[]}`),
		"oversized cancel":        []byte(`{"id":"bad","cancel":"` + strings.Repeat("x", 129) + `"}`),
		"null cancel":             []byte(`{"id":"bad","cancel":null}`),
	}
}

func TestNativeMalformedMessageDoesNotCloseNextRequest(t *testing.T) {
	for name, malformed := range nativeSecurityMalformedMessages() {
		t.Run(name, func(t *testing.T) {
			bridge, back := fixtureBridge(t)
			good := nativeSecurityRequest("good", "https://other.example", "eth_chainId", []any{})
			in := bytes.NewReader(append(nativeSecurityFrame(malformed), nativeSecurityFrame(good)...))
			var out bytes.Buffer
			if e := Serve(context.Background(), bridge, in, &out); e != nil {
				t.Fatal("a complete malformed message terminated the native connection:", e)
			}
			found := false
			for out.Len() > 0 {
				response, e := nativeSecurityRead(&out)
				if e != nil {
					t.Fatal(e)
				}
				if response.ID == "good" {
					if response.Error != nil || response.Result != "0x1" {
						t.Fatalf("subsequent valid call failed: %+v", response)
					}
					found = true
				} else if response.Error == nil {
					t.Fatalf("malformed request was executed: %+v", response)
				}
			}
			if !found {
				t.Fatal("subsequent valid call received no response")
			}
			if back.controls != 0 || back.signatures != 0 {
				t.Fatal("malformed request reached an approval or signing backend")
			}
		})
	}
}

type nativeSecurityWaitingBackend struct {
	Backend
	started chan context.Context
	proceed chan struct{}
}

func (b *nativeSecurityWaitingBackend) Control(ctx context.Context, c vaultwire.WalletControl) (vaultwire.WalletControlResult, error) {
	select {
	case b.started <- ctx:
	case <-ctx.Done():
		return vaultwire.WalletControlResult{}, ctx.Err()
	}
	select {
	case <-b.proceed:
		return b.Backend.Control(ctx, c)
	case <-ctx.Done():
		return vaultwire.WalletControlResult{}, ctx.Err()
	}
}

func TestNativeMalformedMessagePreservesOtherTabApproval(t *testing.T) {
	bridge, back := fixtureBridge(t)
	waiting := &nativeSecurityWaitingBackend{Backend: back, started: make(chan context.Context, 1), proceed: make(chan struct{})}
	bridge.Backend = waiting
	in, send := io.Pipe()
	receive, out := io.Pipe()
	done := make(chan error, 1)
	responses := make(chan NativeResponse, 64)
	readErrors := make(chan error, 1)
	go func() { done <- Serve(context.Background(), bridge, in, out); out.Close() }()
	go func() {
		for {
			response, e := nativeSecurityRead(receive)
			if e != nil {
				readErrors <- e
				return
			}
			responses <- response
		}
	}()
	t.Cleanup(func() { send.Close(); in.Close(); receive.Close(); out.Close() })
	sendRequest := func(raw []byte) {
		t.Helper()
		if _, e := send.Write(nativeSecurityFrame(raw)); e != nil {
			t.Fatal(e)
		}
	}
	awaitResponse := func(id string) NativeResponse {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case response := <-responses:
				if response.ID == id {
					return response
				}
				if response.ID == "pending" {
					t.Fatalf("another tab's approval ended before user consent: %+v", response)
				}
				if response.Error == nil {
					t.Fatalf("malformed request succeeded: %+v", response)
				}
			case e := <-readErrors:
				t.Fatal("native stream closed while another tab waited for approval:", e)
			case <-deadline:
				t.Fatal("native response timed out:", id)
			}
		}
	}
	sendRequest(nativeSecurityRequest("pending", "https://pending.example", "eth_requestAccounts", []any{}))
	var approval context.Context
	select {
	case approval = <-waiting.started:
	case <-time.After(5 * time.Second):
		t.Fatal("approval was not started")
	}
	for name, malformed := range nativeSecurityMalformedMessages() {
		sendRequest(malformed)
		id := "after-" + name
		sendRequest(nativeSecurityRequest(id, "https://malicious.example", "eth_chainId", []any{}))
		response := awaitResponse(id)
		if response.Error != nil || response.Result != "0x1" {
			t.Fatalf("valid request after %q failed: %+v", name, response)
		}
		if approval.Err() != nil {
			t.Fatalf("malformed %q cancelled another tab's approval: %v", name, approval.Err())
		}
	}
	close(waiting.proceed)
	response := awaitResponse("pending")
	accounts, ok := response.Result.([]any)
	if response.Error != nil || !ok || len(accounts) != 1 || accounts[0] != back.catalog.Identities[0].Address {
		t.Fatalf("original user approval could not complete: %+v", response)
	}
	send.Close()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native host failed to close after EOF")
	}
}

func TestNativeCanonicalCancelAndMethodSyntax(t *testing.T) {
	q, e := decodeNativeRequest([]byte(`{"id":"cancel-id","cancel":"pending-id"}`))
	if e != nil || q.Cancel != "pending-id" {
		t.Fatal("canonical cancellation was rejected", e)
	}
	for _, method := range []string{"personal_sign", "eth_signTypedData_v4", "wallet_switchEthereumChain", "_state", "_changeIdentity"} {
		if _, e := decodeNativeRequest(nativeSecurityRequest("valid", "https://example.com", method, []any{})); e != nil {
			t.Fatalf("valid method %q was rejected: %v", method, e)
		}
	}
	for _, method := range []string{"", "éth_chainId", "eth_🔒", "eth_chainId\n", "eth_chainId/", "1eth_chainId", strings.Repeat("a", 81)} {
		if _, e := decodeNativeRequest(nativeSecurityRequest("invalid", "https://example.com", method, []any{})); e == nil {
			t.Fatalf("invalid method %q accepted", method)
		}
	}
}
