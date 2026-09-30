// Package ageio streams age documents locally. Only headers go to a key worker.
package ageio

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"github.com/grexie/vault/internal/limits"
)

func ParseRecipient(value string) (age.Recipient, error) {
	value = strings.TrimSpace(value)
	switch {
	case strings.HasPrefix(value, "ssh-"):
		return agessh.ParseRecipient(value)
	case strings.HasPrefix(value, "age1pq1"):
		return age.ParseHybridRecipient(value)
	default:
		return age.ParseX25519Recipient(value)
	}
}

func Encrypt(dst io.Writer, src io.Reader, recipients []age.Recipient, armored bool) error {
	if len(recipients) == 0 {
		return errors.New("at least one public recipient is required")
	}
	var a io.WriteCloser
	if armored {
		a = armor.NewWriter(dst)
		dst = a
	}
	w, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return err
	}
	if _, err = io.Copy(w, src); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	if a != nil {
		return a.Close()
	}
	return nil
}

func Decrypt(dst io.Writer, src io.Reader, unwrap func([]byte) ([]byte, error)) error {
	b := bufio.NewReader(src)
	magic, _ := b.Peek(len(armor.Header))
	src = b
	if string(magic) == armor.Header {
		src = armor.NewReader(b)
	}
	// ExtractHeader may read ahead. Replay every consumed byte so stdin needs no
	// seeking, temporary ciphertext, or complete document buffering.
	var prefix bytes.Buffer
	header, err := age.ExtractHeader(io.TeeReader(io.LimitReader(src, limits.MaxAgeHeader+1), &prefix))
	if err != nil {
		return fmt.Errorf("invalid or oversized age header: %w", err)
	}
	if len(header) > limits.MaxAgeHeader {
		return errors.New("age header exceeds 64 KiB")
	}
	fileKey, err := unwrap(header)
	if err != nil {
		return err
	}
	defer clear(fileKey)
	if len(fileKey) != 16 {
		return errors.New("invalid age file key")
	}
	plain, err := age.Decrypt(io.MultiReader(bytes.NewReader(prefix.Bytes()), src), age.NewInjectedFileKeyIdentity(fileKey))
	if err != nil {
		return err
	}
	clear(fileKey)
	_, err = io.Copy(dst, plain)
	return err
}
