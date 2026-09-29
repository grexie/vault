//go:build unix

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/grexie/remote-ssh-agent/internal/ageio"
	"github.com/grexie/remote-ssh-agent/internal/app"
	"github.com/grexie/remote-ssh-agent/internal/bridge"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func cryptCommand(ctx context.Context, operation string, args []string) (err error) {
	f := flags(operation)
	config := f.String("config", bridge.DefaultConfigPath(), "paired CLI configuration")
	output := f.String("output", "-", "output file (must not exist); - for stdout")
	f.StringVar(output, "o", "-", "output file; - for stdout")
	var recipients, recipientFiles stringsFlag
	var armored bool
	var session, reason string
	var timeout time.Duration
	if operation == "encrypt" {
		f.Var(&recipients, "recipient", "public age or SSH recipient; repeat for multiple recipients")
		f.Var(&recipients, "r", "public age or SSH recipient")
		f.Var(&recipientFiles, "recipients-file", "file containing public recipients (not private identities)")
		f.Var(&recipientFiles, "R", "file containing public recipients")
		f.BoolVar(&armored, "armor", false, "produce ASCII-armored age output")
		f.BoolVar(&armored, "a", false, "produce ASCII-armored age output")
	} else {
		f.StringVar(&session, "session", "", "reuse an approved age lease (instead of one-shot approval)")
		f.StringVar(&reason, "reason", "", "justification for one-shot document approval; no lease or socket is created")
		f.DurationVar(&timeout, "timeout", 5*time.Minute, "maximum approval wait")
	}
	if err = f.Parse(args); err != nil {
		return err
	}
	if f.NArg() > 1 {
		return errors.New("provide one input path, or - for stdin; place flags before the input")
	}
	input := "-"
	if f.NArg() == 1 {
		input = f.Arg(0)
	}
	if operation == "encrypt" {
		for _, path := range recipientFiles {
			if path == "-" {
				return errors.New("use --recipient or a recipient file; stdin is reserved for document input")
			}
			file, e := os.Open(path)
			if e != nil {
				return e
			}
			contents, readErr := io.ReadAll(io.LimitReader(file, 1024*1024+1))
			file.Close()
			if readErr != nil {
				return readErr
			}
			if len(contents) > 1024*1024 {
				return errors.New("recipient file exceeds 1 MiB")
			}
			scan := bufio.NewScanner(strings.NewReader(string(contents)))
			for scan.Scan() {
				line := strings.TrimSpace(scan.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					recipients = append(recipients, line)
				}
			}
			e = scan.Err()
			if e != nil {
				return fmt.Errorf("invalid recipient file: %w", e)
			}
		}
		if len(recipients) == 0 {
			c, e := bridge.Load(*config)
			if e != nil {
				return e
			}
			public, e := bridge.AgeRecipient(ctx, c)
			if e != nil {
				return e
			}
			recipients = append(recipients, public)
		}
		var parsed []age.Recipient
		for _, value := range recipients {
			r, e := ageio.ParseRecipient(value)
			if e != nil {
				return errors.New("invalid public recipient; use an age public key or an RSA/Ed25519 SSH public key")
			}
			parsed = append(parsed, r)
		}
		return cryptFiles(input, *output, func(out io.Writer, in io.Reader) error { return ageio.Encrypt(out, in, parsed, armored) })
	}
	if session != "" && (!app.SessionPattern.MatchString(session) || reason != "") {
		return errors.New("use either --session for an existing age lease or --reason for one-shot approval")
	}
	if session == "" && (len(strings.TrimSpace(reason)) < 8 || len(reason) > 1000) {
		return errors.New("one-shot decryption requires --reason (8–1000 characters), or use --session for an approved lease")
	}
	c, err := bridge.Load(*config)
	if err != nil {
		return err
	}
	return cryptFiles(input, *output, func(out io.Writer, in io.Reader) error {
		return ageio.Decrypt(out, in, func(header []byte) ([]byte, error) {
			if session == "" {
				waitCtx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				return bridge.DecryptAgeOnce(waitCtx, c, reason, header, func(m string) { fmt.Fprintln(os.Stderr, m) })
			}
			return bridge.DecryptAgeHeader(ctx, c, session, header)
		})
	})
}

// Output files are private and exclusive; failures remove only the new file.
// Streaming stdout cannot retract already emitted plaintext on a later error.
func cryptFiles(input, output string, transform func(io.Writer, io.Reader) error) (err error) {
	var in io.Reader = os.Stdin
	if input != "-" {
		file, e := os.Open(input)
		if e != nil {
			return e
		}
		defer file.Close()
		in = file
	}
	var out io.Writer = os.Stdout
	var file *os.File
	if output != "-" {
		file, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		out = file
		defer func() {
			if e := file.Close(); err == nil {
				err = e
			}
			if err != nil {
				_ = os.Remove(output)
			}
		}()
	}
	return transform(out, in)
}
