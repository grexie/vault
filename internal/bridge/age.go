package bridge

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/grexie/vault/internal/access"
	"github.com/grexie/vault/internal/app"
	"github.com/grexie/vault/internal/signer"
)

func AgeRecipient(ctx context.Context, c Config) (string, error) {
	var reply struct {
		Recipient string `json:"recipient"`
	}
	err := New(c).Call(ctx, "GET", "/v1/recipient", c.Token, nil, &reply)
	return reply.Recipient, err
}

// DecryptAgeOnce creates no on-disk lease, bridge process, or agent socket.
// The approval is bound to this header and consumed by the first decryption.
func DecryptAgeOnce(ctx context.Context, c Config, reason string, header []byte, progress func(string)) ([]byte, error) {
	nonce := make([]byte, 9)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	hash := sha256.Sum256(header)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var grant Lease
	client := New(c)
	if err := client.Call(ctx, "POST", "/v1/requests", c.Token, map[string]any{
		"session": "decrypt-" + base64.RawURLEncoding.EncodeToString(nonce), "reason": reason,
		"access": access.Age, "mode": "age-once", "requestKey": public, "headerHash": base64.RawURLEncoding.EncodeToString(hash[:]),
	}, &grant); err != nil {
		return nil, err
	}
	grant.Config = c
	grant.SigningKey = private
	client = leaseClient(grant)
	defer func() {
		cancelCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = client.Call(cancelCtx, "POST", "/v1/requests/"+grant.Request.ID+"/revoke", grant.Capability, map[string]any{}, nil)
	}()
	if progress != nil {
		progress("Waiting for approval to decrypt this document once…")
	}
	for {
		var q app.Request
		if err := client.Call(ctx, "GET", "/v1/requests/"+grant.Request.ID, grant.Capability, nil, &q); err != nil {
			return nil, err
		}
		if q.Status == "active" {
			break
		}
		if q.Status != "pending" {
			return nil, fmt.Errorf("decryption %s: %s", q.Status, q.EndReason)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return decryptAgeHeader(ctx, client, grant, header)
}

func DecryptAgeHeader(ctx context.Context, c Config, session string, header []byte) ([]byte, error) {
	l, _, _, err := loadLease(c, session)
	if err != nil {
		return nil, err
	}
	if !access.AllowsAge(l.Request.Access) {
		return nil, errors.New("this lease does not allow age decryption; request a new lease with --access age")
	}
	return decryptAgeHeader(ctx, leaseClient(l), l, header)
}

func decryptAgeHeader(ctx context.Context, client *Client, l Lease, header []byte) ([]byte, error) {
	var reply signer.Reply
	if err := client.Call(ctx, "POST", "/v1/requests/"+l.Request.ID+"/age", l.Capability, map[string]any{"header": header}, &reply); err != nil {
		clear(reply.FileKey)
		return nil, err
	}
	if len(reply.FileKey) != 16 {
		clear(reply.FileKey)
		return nil, errors.New("invalid age file key response")
	}
	return reply.FileKey, nil
}
