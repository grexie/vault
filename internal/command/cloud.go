//go:build unix

package command

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/grexie/vault/internal/cloud"
	"github.com/grexie/vault/internal/cloudstore"
	"github.com/grexie/vault/web"
)

func envDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func cloudCommand(ctx context.Context, args []string) error {
	f := flags("cloud")
	origin := f.String("origin", os.Getenv("VAULT_ORIGIN"), "public HTTPS origin")
	listen := f.String("listen", envDefault("VAULT_LISTEN", "127.0.0.1:8791"), "HTTP listen address behind HTTPS ingress")
	keyFile := f.String("storage-key-file", os.Getenv("VAULT_STORAGE_KEY_FILE"), "owner-only file containing 32 random bytes")
	uriFile := f.String("mongodb-uri-file", os.Getenv("VAULT_MONGODB_URI_FILE"), "owner-only MongoDB URI file")
	trusted := f.String("trusted-proxies", os.Getenv("VAULT_TRUSTED_PROXIES"), "comma-separated trusted ingress peer CIDRs; empty ignores forwarded headers")
	database := f.String("database", envDefault("VAULT_MONGODB_DATABASE", "grexie_vault"), "MongoDB database")
	development := f.Bool("development", false, "allow HTTP on a literal loopback origin for isolated tests")
	privateMongo := f.Bool("private-mongodb", os.Getenv("VAULT_MONGODB_ALLOW_PRIVATE_PLAINTEXT") == "true", "explicitly allow a trusted private MongoDB transport without TLS")
	if e := f.Parse(args); e != nil {
		return e
	}
	key, e := cloudstore.ReadStorageKey(*keyFile)
	if e != nil {
		return e
	}
	defer clear(key)
	uri, e := cloudstore.ReadSecret(*uriFile, 4096)
	if e != nil {
		return e
	}
	defer clear(uri)
	mongoURI := strings.TrimSpace(string(uri))
	if e = cloudstore.ValidateMongoURI(mongoURI, *privateMongo); e != nil {
		return e
	}
	connect, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	store, e := cloudstore.Connect(connect, mongoURI, *database, key)
	if e != nil {
		return errors.New("cannot connect to encrypted MongoDB storage; check local configuration")
	}
	defer store.Close(context.Background())
	var proxies []string
	if *trusted != "" {
		proxies = strings.Split(*trusted, ",")
	}
	s, e := cloud.New(ctx, cloud.Config{Origin: *origin, Version: version, Development: *development, TrustedProxyCIDRs: proxies}, store, web.VaultHandler())
	if e != nil {
		return e
	}
	server := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 * 1024}
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(stop)
	}()
	fmt.Fprintln(os.Stderr, "Grexie Vault", version, "listening on", *listen)
	if e = server.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
		return e
	}
	return nil
}
func storageKeyCommand(args []string) error {
	f := flags("storage-key")
	path := f.String("out", "", "new local owner-only key file (required)")
	if e := f.Parse(args); e != nil {
		return e
	}
	if *path == "" {
		return errors.New("--out is required; encryption keys are never printed")
	}
	out, e := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errors.New("cannot create key file; existing files are never replaced")
	}
	key := make([]byte, 32)
	defer clear(key)
	if _, e = rand.Read(key); e != nil {
		out.Close()
		os.Remove(*path)
		return e
	}
	_, e = out.Write(key)
	if e == nil {
		e = out.Sync()
	}
	closed := out.Close()
	if e != nil {
		os.Remove(*path)
		return errors.New("could not persist encryption key")
	}
	if closed != nil {
		return closed
	}
	fmt.Fprintln(os.Stderr, "Created local storage encryption key. Back it up separately from MongoDB.")
	return nil
}
