//go:build unix

package provider

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecurityReviewDockerHelperKeepsCredentialsOffDisk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Keep the fixture path below Darwin's short Unix-socket pathname limit.
	dir, err := os.MkdirTemp("/tmp", "vault-helper-review-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	credential := Credentials{Provider: "docker", Fields: map[string]string{"server": "registry.example", "username": "review-fixture-user", "password": "review-fixture-long-secret-only"}}
	env, closeHelper, err := dockerHelper(ctx, dir, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer closeHelper()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", env["VAULT_DOCKER_HELPER_SOCKET"])
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	callOperation := func(operation, payload, token string) (int, []byte, error) {
		r, e := http.NewRequestWithContext(context.Background(), "POST", "http://local/"+operation, strings.NewReader(payload))
		if e != nil {
			return 0, nil, e
		}
		r.Header.Set("Authorization", "Bearer "+token)
		response, e := client.Do(r)
		if e != nil {
			return 0, nil, e
		}
		defer response.Body.Close()
		b, e := io.ReadAll(io.LimitReader(response.Body, 4096))
		return response.StatusCode, b, e
	}
	call := func(registry, token string) (int, []byte, error) {
		return callOperation("get", registry, token)
	}
	if code, _, err := call("other-registry.example", env["VAULT_DOCKER_HELPER_TOKEN"]); err != nil || code != 403 {
		t.Fatal("unapproved registry accepted", code, err)
	}
	if code, _, err := call(credential.Fields["server"], "incorrect-token"); err != nil || code != 403 {
		t.Fatal("missing capability accepted", code, err)
	}
	code, raw, err := call(credential.Fields["server"], env["VAULT_DOCKER_HELPER_TOKEN"])
	if err != nil || code != 200 {
		t.Fatal("approved helper failed", code, err)
	}
	var result map[string]string
	if json.Unmarshal(raw, &result) != nil || result["Username"] != credential.Fields["username"] || result["Secret"] != credential.Fields["password"] {
		t.Fatal("helper returned wrong credential")
	}
	storeBody := func(server, username, secret string) string {
		b, err := json.Marshal(map[string]string{"ServerURL": server, "Username": username, "Secret": secret})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	approvedStore := storeBody(credential.Fields["server"], credential.Fields["username"], credential.Fields["password"])
	if code, response, err := callOperation("store", approvedStore, env["VAULT_DOCKER_HELPER_TOKEN"]); err != nil || code != 200 || len(response) != 0 {
		t.Fatal("Docker login could not confirm approved credential", code, err)
	}
	for name, body := range map[string]string{
		"different registry": storeBody("other-registry.example", credential.Fields["username"], credential.Fields["password"]),
		"different username": storeBody(credential.Fields["server"], "different-user", credential.Fields["password"]),
		"different secret":   storeBody(credential.Fields["server"], credential.Fields["username"], "replacement-secret"),
		"trailing JSON":      approvedStore + `{}`,
		"unknown fields":     strings.TrimSuffix(approvedStore, "}") + `,"extra":"value"}`,
		"empty credential":   `{}`,
	} {
		if code, _, err := callOperation("store", body, env["VAULT_DOCKER_HELPER_TOKEN"]); err != nil || code != 403 {
			t.Error(name, "was not refused", code, err)
		}
	}
	if code, _, err := callOperation("store", approvedStore, "incorrect-token"); err != nil || code != 403 {
		t.Fatal("store without the capability accepted", code, err)
	}
	if code, _, err := callOperation("erase", credential.Fields["server"], env["VAULT_DOCKER_HELPER_TOKEN"]); err != nil || code != 403 {
		t.Fatal("credential erasure accepted", code, err)
	}
	code, afterStore, err := call(credential.Fields["server"], env["VAULT_DOCKER_HELPER_TOKEN"])
	if err != nil || code != 200 || !bytes.Equal(raw, afterStore) {
		t.Fatal("store changed the approved credential", code, err)
	}
	checkFiles := func() {
		t.Helper()
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, secret := range []string{credential.Fields["password"], credential.Fields["username"], base64.StdEncoding.EncodeToString([]byte(credential.Fields["username"] + ":" + credential.Fields["password"])), env["VAULT_DOCKER_HELPER_TOKEN"]} {
				if bytes.Contains(b, []byte(secret)) {
					t.Errorf("secret persisted in %s", filepath.Base(path))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	checkFiles()
	if st, err := os.Stat(env["VAULT_DOCKER_HELPER_SOCKET"]); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("helper socket permissions", err)
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		_, _, err := call(credential.Fields["server"], env["VAULT_DOCKER_HELPER_TOKEN"])
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("helper continued releasing credentials after cancellation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Files may survive an abrupt exit, but they contain no login material.
	checkFiles()
}
