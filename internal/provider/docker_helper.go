//go:build unix

package provider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Docker gets credentials from this process's memory. Temporary files contain
// only the helper name, so even SIGKILL cannot strand a token in config.json.
func dockerHelper(ctx context.Context, dir string, c Credentials) (map[string]string, func(), error) {
	path := filepath.Join(dir, "helper.sock")
	listener, e := net.Listen("unix", path)
	if e != nil {
		return nil, nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		listener.Close()
		return nil, nil, e
	}
	random := make([]byte, 32)
	if _, e = rand.Read(random); e != nil {
		listener.Close()
		return nil, nil, e
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	clear(random)
	server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/get" || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			http.Error(w, "denied", 403)
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		if e != nil || strings.TrimSpace(string(b)) != c.Fields["server"] {
			http.Error(w, "registry not approved", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Username": c.Fields["username"], "Secret": c.Fields["password"]})
	})}
	go server.Serve(listener)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	closeFn := func() { close(done); server.Close() }
	exe, e := os.Executable()
	if e != nil {
		closeFn()
		return nil, nil, e
	}
	helperDir := filepath.Join(dir, "bin")
	if e = os.Mkdir(helperDir, 0700); e != nil {
		closeFn()
		return nil, nil, e
	}
	if e = os.Symlink(exe, filepath.Join(helperDir, "docker-credential-grexie-vault")); e != nil {
		closeFn()
		return nil, nil, e
	}
	config, _ := json.Marshal(map[string]any{"credHelpers": map[string]string{c.Fields["server"]: "grexie-vault"}})
	if e = os.WriteFile(filepath.Join(dir, "config.json"), config, 0600); e != nil {
		closeFn()
		return nil, nil, e
	}
	return map[string]string{"VAULT_DOCKER_HELPER_SOCKET": path, "VAULT_DOCKER_HELPER_TOKEN": token, "PATH": helperDir + string(os.PathListSeparator) + os.Getenv("PATH")}, closeFn, nil
}
func DockerCredentialHelper(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] != "get" {
		return errors.New("this temporary helper only retrieves the approved registry credential")
	}
	socket, token := os.Getenv("VAULT_DOCKER_HELPER_SOCKET"), os.Getenv("VAULT_DOCKER_HELPER_TOKEN")
	if socket == "" || token == "" {
		return errors.New("Docker credential approval has ended")
	}
	registry, e := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if e != nil || len(registry) > 4096 {
		return errors.New("invalid registry")
	}
	defer clear(registry)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://local/get", bytes.NewReader(registry))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, e := client.Do(req)
	if e != nil {
		return errors.New("Docker credential approval has ended")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("registry is not approved")
	}
	_, e = io.Copy(os.Stdout, io.LimitReader(response.Body, 1024*1024))
	return e
}
