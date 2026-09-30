package device

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/grexie/vault/internal/vaultwire"
	"io"
	"net/http"
	"time"
)

func (c *Client) RPC(ctx context.Context, endpoint string, p Pending, state vaultwire.RequestState, method string, data []byte) ([]byte, error) {
	if e := ValidateServer(endpoint); e != nil {
		return nil, e
	}
	authorization, receiver, e := c.Authorization(p, state)
	if e != nil {
		return nil, e
	}
	replyKey, e := vaultwire.NewKey()
	if e != nil {
		return nil, e
	}
	q := vaultwire.RPC{RequestID: p.Request.ID, Nonce: RandomID(), Method: method, Data: data, ReplyPublic: replyKey.PublicKey().Bytes(), ExpiresAt: time.Now().Add(30 * time.Second)}
	signed, e := vaultwire.Sign(c.Config.PrivateKey, "rpc", q)
	if e != nil {
		return nil, e
	}
	raw, _ := json.Marshal(signed)
	defer clear(raw)
	box, e := vaultwire.Seal(receiver.PublicKey, "rpc:"+q.RequestID, raw)
	if e != nil {
		return nil, e
	}
	body, _ := json.Marshal(map[string]any{"requestId": q.RequestID, "box": box})
	defer clear(body)
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint+"/v1/rpc", bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := c.HTTP.Do(req)
	if e != nil {
		return nil, errors.New("cannot reach the selected signing device")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		if response.StatusCode == 423 {
			return nil, ErrPending
		}
		return nil, errors.New("signing device refused this operation")
	}
	encrypted, e := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1))
	if e != nil || len(encrypted) > 8*1024*1024 {
		return nil, errors.New("invalid device response")
	}
	var responseBox vaultwire.Envelope
	if json.Unmarshal(encrypted, &responseBox) != nil {
		return nil, errors.New("invalid encrypted response")
	}
	plain, e := vaultwire.Open(replyKey.Bytes(), "rpc-response:"+q.RequestID+":"+q.Nonce, responseBox)
	if e != nil {
		return nil, errors.New("device reply could not be opened")
	}
	defer clear(plain)
	var signature vaultwire.Signed
	var result vaultwire.RPCResult
	if json.Unmarshal(plain, &signature) != nil || vaultwire.Verify(authorization.AgentPublic, "rpc-response", signature, &result) != nil || result.Nonce != q.Nonce || result.RequestHash != vaultwire.Digest(signed.Payload) {
		return nil, errors.New("device reply signature or scope rejected")
	}
	if result.Error != "" {
		return nil, errors.New(result.Error)
	}
	return result.Data, nil
}
