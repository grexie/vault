//go:build unix

package browserwallet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/grexie/vault/internal/walletsign"
)

const HostName = "com.grexie.vault"

// ExtensionID is derived from the public manifest key shipped in extension/.
// The corresponding private key is not needed by an unpacked installation.
const ExtensionID = "kocbneijhmklhomjnmjaopgdpciamann"

type NativeRequest struct {
	ID     string          `json:"id"`
	Origin string          `json:"origin"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	Cancel string          `json:"cancel,omitempty"`
}
type NativeResponse struct {
	ID     string `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// The envelope is decoded separately from params: a site's malformed wallet
// parameters must not tear down the native connection shared by other tabs.
// Only canonical, unambiguous IDs may receive an error response.
func decodeNativeRequest(raw []byte) (NativeRequest, error) {
	var q NativeRequest
	invalid := errors.New("invalid native request")
	if !utf8.Valid(raw) {
		return q, invalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if start, e := d.Token(); e != nil || start != json.Delim('{') {
		return q, invalid
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		field, e := d.Token()
		if e != nil {
			return q, invalid
		}
		name, ok := field.(string)
		if !ok {
			return q, invalid
		}
		switch name {
		case "id", "origin", "method", "params", "cancel":
		default:
			return q, invalid
		}
		if _, exists := fields[name]; exists {
			return q, invalid
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return q, invalid
		}
		fields[name] = value
	}
	if end, e := d.Token(); e != nil || end != json.Delim('}') {
		return q, invalid
	}
	if _, e := d.Token(); e != io.EOF {
		return q, invalid
	}
	if json.Unmarshal(fields["id"], &q.ID) != nil || len(q.ID) == 0 || len(q.ID) > 128 {
		return NativeRequest{}, invalid
	}
	for name, target := range map[string]*string{"origin": &q.Origin, "method": &q.Method, "cancel": &q.Cancel} {
		if value, exists := fields[name]; exists && (bytes.Equal(value, []byte("null")) || json.Unmarshal(value, target) != nil) {
			return q, invalid
		}
	}
	q.Params = fields["params"]
	if q.Cancel != "" {
		if len(q.Cancel) > 128 || len(fields) != 2 {
			return q, invalid
		}
		return q, nil
	}
	if _, exists := fields["cancel"]; exists || len(q.Origin) == 0 || len(q.Origin) > 512 || !nativeMethod(q.Method) {
		return q, invalid
	}
	return q, nil
}

func nativeMethod(method string) bool {
	if len(method) == 0 || len(method) > 80 {
		return false
	}
	for i, c := range []byte(method) {
		if c != '_' && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') && !(i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// Serve uses Chrome's stdin/stdout framing. It never opens a network listener.
func Serve(ctx context.Context, b *Bridge, in io.Reader, out io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var writes sync.Mutex
	var mu sync.Mutex
	pending := map[string]context.CancelFunc{}
	var wg sync.WaitGroup
	defer func() {
		cancel()
		mu.Lock()
		for _, c := range pending {
			c()
		}
		mu.Unlock()
		wg.Wait()
	}()
	write := func(v NativeResponse) {
		raw, e := json.Marshal(v)
		if e != nil || len(raw) > 1000*1024 {
			raw, _ = json.Marshal(NativeResponse{ID: v.ID, Error: &Error{-32603, "Wallet response exceeds native message limit"}})
		}
		header := make([]byte, 4)
		binary.LittleEndian.PutUint32(header, uint32(len(raw)))
		writes.Lock()
		defer writes.Unlock()
		_, _ = out.Write(header)
		_, _ = out.Write(raw)
	}
	r := bufio.NewReader(in)
	for {
		header := make([]byte, 4)
		if _, e := io.ReadFull(r, header); e != nil {
			if e == io.EOF {
				return nil
			}
			return errors.New("native message framing failed")
		}
		n := binary.LittleEndian.Uint32(header)
		if n == 0 || n > walletsign.MaxPayload {
			return errors.New("native message size exceeds limit")
		}
		raw := make([]byte, n)
		if _, e := io.ReadFull(r, raw); e != nil {
			return errors.New("incomplete native message")
		}
		q, e := decodeNativeRequest(raw)
		if e != nil {
			if q.ID != "" {
				write(NativeResponse{ID: q.ID, Error: &Error{-32600, "Invalid native wallet request"}})
			}
			continue
		}
		if q.Cancel != "" {
			mu.Lock()
			if c := pending[q.Cancel]; c != nil {
				c()
			}
			mu.Unlock()
			continue
		}
		mu.Lock()
		if _, exists := pending[q.ID]; exists || len(pending) >= 16 {
			mu.Unlock()
			write(NativeResponse{ID: q.ID, Error: &Error{-32002, "Too many pending wallet requests"}})
			continue
		}
		work, stop := context.WithTimeout(ctx, 12*time.Minute)
		pending[q.ID] = stop
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer stop()
			defer func() { mu.Lock(); delete(pending, q.ID); mu.Unlock() }()
			v, e := b.Call(work, q.Origin, q.Method, q.Params)
			response := NativeResponse{ID: q.ID, Result: v}
			if e != nil {
				var pe *Error
				if errors.As(e, &pe) {
					response.Error = pe
				} else {
					response.Error = &Error{-32603, "Vault request failed"}
				}
				response.Result = nil
			}
			write(response)
		}()
	}
}
