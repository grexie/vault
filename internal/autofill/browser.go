package autofill

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

//go:embed page.js
var pageScript string

type Target struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	Type      string `json:"type"`
	WebSocket string `json:"webSocketDebuggerUrl,omitempty"`
}
type Inspection struct {
	Origin        string   `json:"origin"`
	DocumentToken string   `json:"documentToken"`
	Fields        []string `json:"fields"`
}
type Browser interface {
	Inspect(context.Context) (Inspection, error)
	Fill(context.Context, Inspection, map[string]string) (int, error)
	Close() error
}

func localURL(endpoint string) (*url.URL, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return nil, errors.New("CDP endpoint must be a literal loopback HTTP origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("CDP is restricted to a literal loopback address")
	}
	return u, nil
}
func ChromeTargets(ctx context.Context, endpoint string) ([]Target, error) {
	u, e := localURL(endpoint)
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(u.String(), "/")+"/json/list", nil)
	if e != nil {
		return nil, e
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, e := client.Do(r)
	if e != nil {
		return nil, errors.New("Chrome debugging endpoint is unavailable; connect a local automation browser")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("Chrome target lookup failed")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 2*1024*1024+1))
	if e != nil || len(b) > 2*1024*1024 {
		return nil, errors.New("invalid Chrome target response")
	}
	var targets []Target
	if json.Unmarshal(b, &targets) != nil {
		return nil, errors.New("invalid Chrome target list")
	}
	out := []Target{}
	for _, t := range targets {
		if t.Type == "page" {
			out = append(out, t)
		}
	}
	return out, nil
}

type Chrome struct {
	conn  *websocket.Conn
	next  int
	world int
}

func OpenChrome(ctx context.Context, endpoint, target, frame string) (*Chrome, error) {
	u, e := localURL(endpoint)
	if e != nil {
		return nil, e
	}
	targets, e := ChromeTargets(ctx, endpoint)
	if e != nil {
		return nil, e
	}
	var ws string
	for _, t := range targets {
		if t.ID == target {
			ws = t.WebSocket
			break
		}
	}
	w, e := url.Parse(ws)
	if e != nil || w.Scheme != "ws" || w.Host != u.Host || w.User != nil || w.Fragment != "" || w.RawQuery != "" {
		return nil, errors.New("target is missing or uses an untrusted debugging endpoint")
	}
	dialer := websocket.Dialer{Proxy: nil, HandshakeTimeout: 5 * time.Second}
	conn, _, e := dialer.DialContext(ctx, ws, nil)
	if e != nil {
		return nil, errors.New("could not connect to Chrome target")
	}
	conn.SetReadLimit(2 * 1024 * 1024)
	c := &Chrome{conn: conn}
	if frame == "" {
		var result struct {
			FrameTree struct {
				Frame struct {
					ID string `json:"id"`
				} `json:"frame"`
			} `json:"frameTree"`
		}
		if e = c.call(ctx, "Page.getFrameTree", struct{}{}, &result); e != nil {
			c.Close()
			return nil, e
		}
		frame = result.FrameTree.Frame.ID
	}
	var world struct {
		ID int `json:"executionContextId"`
	}
	if e = c.call(ctx, "Page.createIsolatedWorld", map[string]any{"frameId": frame, "worldName": "GrexieVaultAutofill"}, &world); e != nil {
		c.Close()
		return nil, e
	}
	c.world = world.ID
	return c, nil
}
func (c *Chrome) call(ctx context.Context, method string, params, out any) error {
	c.next++
	deadline := time.Now().Add(8 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.conn.SetWriteDeadline(deadline)
	c.conn.SetReadDeadline(deadline)
	if e := c.conn.WriteJSON(map[string]any{"id": c.next, "method": method, "params": params}); e != nil {
		return errors.New("browser connection closed")
	}
	for {
		var response struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if e := c.conn.ReadJSON(&response); e != nil {
			return errors.New("browser response unavailable")
		}
		if response.ID != c.next {
			continue
		}
		if len(response.Error) > 0 {
			return errors.New("browser operation refused; the page may have changed")
		}
		if out != nil {
			return json.Unmarshal(response.Result, out)
		}
		return nil
	}
}
func (c *Chrome) execute(ctx context.Context, action string, expected Inspection, values map[string]string, out any) error {
	var result struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exception json.RawMessage `json:"exceptionDetails"`
	}
	params := map[string]any{"executionContextId": c.world, "functionDeclaration": fmt.Sprintf("function(action, expected, values) { %s; return vaultPage(action, expected, values); }", pageScript), "arguments": []any{map[string]any{"value": action}, map[string]any{"value": expected}, map[string]any{"value": values}}, "returnByValue": true, "awaitPromise": false}
	if e := c.call(ctx, "Runtime.callFunctionOn", params, &result); e != nil {
		return e
	}
	if len(result.Exception) > 0 {
		return errors.New("autofill refused: changed page, ambiguous fields, or unsupported form")
	}
	return json.Unmarshal(result.Result.Value, out)
}
func (c *Chrome) Inspect(ctx context.Context) (Inspection, error) {
	var in Inspection
	e := c.execute(ctx, "inspect", Inspection{}, nil, &in)
	return in, e
}
func (c *Chrome) Fill(ctx context.Context, in Inspection, values map[string]string) (int, error) {
	var result struct {
		Filled int `json:"filled"`
	}
	e := c.execute(ctx, "fill", in, values, &result)
	return result.Filled, e
}
func (c *Chrome) Close() error { return c.conn.Close() }
