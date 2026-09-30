package hyperliquid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicViewsIncludeAllVenuesAndKeepUnifiedBalancesSeparate(t *testing.T) {
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/info" {
			t.Error("unexpected destination")
		}
		var q map[string]string
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("invalid body")
		}
		seen[q["type"]+":"+q["dex"]]++
		w.Header().Set("Content-Type", "application/json")
		switch q["type"] {
		case "perpDexs":
			w.Write([]byte(`[null,{"name":"xyz"},{"name":"xyz"}]`))
		case "userAbstraction":
			w.Write([]byte(`"unifiedAccount"`))
		case "spotClearinghouseState":
			w.Write([]byte(`{"balances":[{"coin":"USDC","total":"12.345678"}]}`))
		case "clearinghouseState":
			w.Write([]byte(`{"marginSummary":{"accountValue":"12.345678"},"assetPositions":[{"position":{"coin":"` + q["dex"] + `BTC","szi":"1"}}]}`))
		case "frontendOpenOrders":
			w.Write([]byte(`[{"coin":"` + q["dex"] + `BTC","oid":123}]`))
		default:
			t.Error("non-info action used")
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	client := &InfoClient{endpoint: srv.URL + "/info", http: srv.Client()}
	address := "0x" + strings.Repeat("1", 40)
	b, e := client.Account(context.Background(), "mainnet", address, "balance", "all")
	if e != nil || b.AccountMode != "unifiedAccount" || len(b.Perpetuals) != 2 || !strings.Contains(b.Note, "do not add") || !strings.Contains(string(b.Spot), "12.345678") {
		t.Fatal(b, e)
	}
	p, e := client.Account(context.Background(), "mainnet", address, "positions", "all")
	if e != nil || p.Positions == nil || len(*p.Positions) != 2 || (*p.Positions)[1].DEX != "xyz" {
		t.Fatal(p, e)
	}
	o, e := client.Account(context.Background(), "mainnet", address, "orders", "all")
	if e != nil || o.Orders == nil || len(*o.Orders) != 2 {
		t.Fatal(o, e)
	}
	if seen["frontendOpenOrders:"] != 1 || seen["frontendOpenOrders:xyz"] != 1 {
		t.Fatal("duplicate or missing venue", seen)
	}
	for _, bad := range []string{"../exchange", "https://other.example"} {
		if _, e = client.Account(context.Background(), "mainnet", address, "orders", bad); e == nil {
			t.Fatal("invalid DEX accepted")
		}
	}
}
func TestPublicInfoRejectsOversizedResponsesAndInvalidNetwork(t *testing.T) {
	if _, e := NewInfoClient("other"); e == nil {
		t.Fatal("arbitrary endpoint accepted")
	}
	for _, body := range []string{"not-json", strings.Repeat("x", 4*1024*1024+1)} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
		client := &InfoClient{endpoint: srv.URL, http: srv.Client()}
		var out any
		e := client.query(context.Background(), map[string]string{"type": "perpDexs"}, &out)
		srv.Close()
		if e == nil {
			t.Fatal("invalid response accepted")
		}
	}
}
