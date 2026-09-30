package hyperliquid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

type InfoClient struct {
	endpoint string
	http     *http.Client
}

func NewInfoClient(network string) (*InfoClient, error) {
	url := "https://api.hyperliquid.xyz/info"
	if network == "testnet" {
		url = "https://api.hyperliquid-testnet.xyz/info"
	} else if network != "mainnet" {
		return nil, errors.New("network must be mainnet or testnet")
	}
	return &InfoClient{url, &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Hyperliquid info redirect refused") }}}, nil
}
func (c *InfoClient) query(ctx context.Context, body any, out any) error {
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(b))
	if e != nil {
		return e
	}
	r.Header.Set("Content-Type", "application/json")
	resp, e := c.http.Do(r)
	if e != nil {
		return errors.New("Hyperliquid public info is unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Hyperliquid public info returned HTTP %d", resp.StatusCode)
	}
	b, e = io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if e != nil || len(b) > 4*1024*1024 {
		return errors.New("Hyperliquid public info response exceeds limit")
	}
	if json.Unmarshal(b, out) != nil {
		return errors.New("invalid Hyperliquid public info response")
	}
	return nil
}

var dexRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (c *InfoClient) dexes(ctx context.Context, selection string) ([]string, error) {
	if selection == "native" || selection == "" {
		return []string{""}, nil
	}
	if selection != "all" {
		if !dexRE.MatchString(selection) {
			return nil, errors.New("invalid DEX name")
		}
		return []string{selection}, nil
	}
	var dexes []*struct {
		Name string `json:"name"`
	}
	if e := c.query(ctx, map[string]string{"type": "perpDexs"}, &dexes); e != nil {
		return nil, e
	}
	if len(dexes) > 128 {
		return nil, errors.New("too many perpetuals venues")
	}
	out := []string{""}
	seen := map[string]bool{"": true}
	for _, d := range dexes {
		if d == nil || seen[d.Name] {
			continue
		}
		if !dexRE.MatchString(d.Name) {
			return nil, errors.New("invalid public DEX metadata")
		}
		seen[d.Name] = true
		out = append(out, d.Name)
	}
	return out, nil
}

type MarketItem struct {
	DEX  string          `json:"dex"`
	Data json.RawMessage `json:"data"`
}
type AccountInfo struct {
	Network     string          `json:"network"`
	Address     string          `json:"address"`
	ObservedAt  time.Time       `json:"observedAt"`
	AccountMode string          `json:"accountMode,omitempty"`
	Note        string          `json:"note,omitempty"`
	Spot        json.RawMessage `json:"spot,omitempty"`
	Perpetuals  []MarketItem    `json:"perpetuals,omitempty"`
	Positions   *[]MarketItem   `json:"positions,omitempty"`
	Orders      *[]MarketItem   `json:"orders,omitempty"`
}

// Account returns public state only. It has no reference to Vault approval or
// private identity data, and cannot call Hyperliquid's exchange endpoint.
func (c *InfoClient) Account(ctx context.Context, network, user, view, dex string) (AccountInfo, error) {
	out := AccountInfo{Network: network, Address: user}
	if _, e := address(user); e != nil {
		return out, e
	}
	if view != "balance" && view != "positions" && view != "orders" {
		return out, errors.New("unknown account view")
	}
	dexes, e := c.dexes(ctx, dex)
	if e != nil {
		return out, e
	}
	if view == "balance" {
		if e = c.query(ctx, map[string]string{"type": "userAbstraction", "user": user}, &out.AccountMode); e != nil {
			return out, e
		}
		if e = c.query(ctx, map[string]string{"type": "spotClearinghouseState", "user": user}, &out.Spot); e != nil {
			return out, e
		}
		out.Note = "Spot and perpetuals balances are separate views, not an additive portfolio total. For unifiedAccount or portfolioMargin, spot balances are the trading balance; do not add overlapping perpetuals account values."
	}
	items := []MarketItem{}
	for _, d := range dexes {
		body := map[string]string{"type": "clearinghouseState", "user": user, "dex": d}
		if view == "orders" {
			body["type"] = "frontendOpenOrders"
			var rows []json.RawMessage
			if e = c.query(ctx, body, &rows); e != nil {
				return out, e
			}
			for _, row := range rows {
				items = append(items, MarketItem{d, row})
			}
			continue
		}
		var raw json.RawMessage
		if e = c.query(ctx, body, &raw); e != nil {
			return out, e
		}
		if view == "balance" {
			out.Perpetuals = append(out.Perpetuals, MarketItem{d, raw})
		} else {
			var state struct {
				Positions []json.RawMessage `json:"assetPositions"`
			}
			if json.Unmarshal(raw, &state) != nil {
				return out, errors.New("invalid positions response")
			}
			for _, p := range state.Positions {
				items = append(items, MarketItem{d, p})
			}
		}
	}
	if view == "orders" {
		out.Orders = &items
	}
	if view == "positions" {
		out.Positions = &items
	}
	out.ObservedAt = time.Now().UTC()
	return out, nil
}
