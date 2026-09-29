//go:build unix

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"filippo.io/age"
)

func TestOfflineEncryptionAndOutputSafety(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "plain")
	output := filepath.Join(d, "cipher.age")
	os.WriteFile(input, []byte("generated test document"), 0600)
	identity, _ := age.GenerateX25519Identity()
	err := cryptCommand(context.Background(), "encrypt", []string{"--config", filepath.Join(d, "missing"), "-r", identity.Recipient().String(), "-o", output, input})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := age.Decrypt(f, identity)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "generated test document" {
		t.Fatal("offline encryption failed")
	}
	st, _ := os.Stat(output)
	if st.Mode().Perm() != 0600 {
		t.Fatal("output permissions")
	}
	transform := func(w io.Writer, r io.Reader) error { _, err := io.Copy(w, r); return err }
	if cryptFiles(input, input, transform) == nil || cryptFiles(input, output, transform) == nil {
		t.Fatal("overwrote existing file")
	}
	link := filepath.Join(d, "link")
	os.Symlink(input, link)
	if cryptFiles(input, link, transform) == nil {
		t.Fatal("followed output symlink")
	}
	partial := filepath.Join(d, "partial")
	if cryptFiles(input, partial, func(w io.Writer, r io.Reader) error { w.Write([]byte("partial")); return errors.New("failed") }) == nil {
		t.Fatal("missing error")
	}
	if _, err = os.Stat(partial); !os.IsNotExist(err) {
		t.Fatal("left failed plaintext output")
	}
}

func TestIdleDuration(t *testing.T) {
	for value, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "365d": 365 * 24 * time.Hour, "12h": 12 * time.Hour} {
		got, err := parseIdleDuration(value)
		if err != nil || got != want {
			t.Fatalf("%s: %s %v", value, got, err)
		}
	}
	for _, value := range []string{"0", "-1d", "366d", "9999999999d", "wrong"} {
		if _, err := parseIdleDuration(value); err == nil {
			t.Fatal("invalid idle accepted")
		}
	}
}
