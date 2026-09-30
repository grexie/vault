//go:build unix

package keychain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/provider"
	"github.com/grexie/vault/internal/vaultwire"
)

type ImportPermit struct {
	Request  vaultwire.Signed `json:"request"`
	Response vaultwire.Signed `json:"response"`
}

func socketPath(c device.Config) (string, error) {
	dir := fmt.Sprintf("/tmp/grexie-vault-%d", os.Getuid())
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return "", e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return "", e
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !st.IsDir() || st.Mode().Perm() != 0700 {
		return "", errors.New("unsafe local agent directory")
	}
	return filepath.Join(dir, "keychain-"+vaultwire.Digest([]byte(c.Device.ID))[:12]+".sock"), nil
}
func Serve(ctx context.Context, c device.Config) error {
	path, e := socketPath(c)
	if e != nil {
		return e
	}
	listener, e := net.Listen("unix", path)
	if e != nil {
		return errors.New("keychain service is already running, or its socket needs manual cleanup")
	}
	defer listener.Close()
	defer os.Remove(path)
	if e = os.Chmod(path, 0600); e != nil {
		return e
	}
	reader := NewReader()
	defer reader.Close()
	var mu sync.Mutex
	used := map[string]time.Time{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/import" {
			http.Error(w, "not found", 404)
			return
		}
		var permit ImportPermit
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&permit) != nil {
			http.Error(w, "invalid import permit", 400)
			return
		}
		var q vaultwire.Request
		var response vaultwire.Response
		if vaultwire.Verify(c.Device.PublicKey, "request", permit.Request, &q) != nil || q.DeviceID != c.Device.ID || q.Kind != "keychain-import" || vaultwire.Verify(c.OwnerPublic, "response", permit.Response, &response) != nil || response.RequestID != q.ID || response.RequestHash != vaultwire.Digest(permit.Request.Payload) || response.Error != "" || !time.Now().Before(response.ExpiresAt) || time.Until(response.ExpiresAt) > 3*time.Minute {
			http.Error(w, "owner approval required", 403)
			return
		}
		var intent Intent
		if json.Unmarshal(q.Payload, &intent) != nil || intent.Validate() != nil {
			http.Error(w, "invalid import scope", 400)
			return
		}
		state, err := device.New(c).Status(r.Context(), q.ID)
		if err != nil || state.Status != "completed" || state.Response == nil || !bytes.Equal(state.Response.Signature, permit.Response.Signature) {
			http.Error(w, "import approval is no longer active", 403)
			return
		}
		mu.Lock()
		_, replayed := used[q.ID]
		if !replayed {
			used[q.ID] = response.ExpiresAt
		}
		for id, end := range used {
			if time.Now().After(end) {
				delete(used, id)
			}
		}
		mu.Unlock()
		if replayed {
			http.Error(w, "permit already used", 409)
			return
		}
		credential, e := reader.Read(r.Context(), intent)
		if e != nil {
			http.Error(w, e.Error(), 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(credential)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 3 * time.Minute}
	go func() { <-ctx.Done(); server.Close() }()
	fmt.Fprintln(os.Stderr, "Local Keychain service ready. Chrome authorization is held in memory until this process exits.")
	e = server.Serve(listener)
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func Import(ctx context.Context, c device.Config, permit ImportPermit) (provider.Credentials, error) {
	var out provider.Credentials
	path, e := socketPath(c)
	if e != nil {
		return out, e
	}
	b, _ := json.Marshal(permit)
	client := &http.Client{Timeout: 3 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	r, _ := http.NewRequestWithContext(ctx, "POST", "http://local/import", bytes.NewReader(b))
	res, e := client.Do(r)
	if e != nil {
		return out, errors.New("start vault keychain serve on this device before a native browser import")
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 1024*1024+1))
	if e != nil || len(raw) > 1024*1024 {
		return out, errors.New("invalid Keychain response")
	}
	defer clear(raw)
	if res.StatusCode != 200 {
		if len(raw) < 300 {
			return out, errors.New(string(bytes.TrimSpace(raw)))
		}
		return out, errors.New("Keychain import refused")
	}
	return provider.DecodeCredentials(raw)
}
