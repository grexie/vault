package hyperliquid

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/grexie/vault/internal/identity"
)

func Review(raw []byte) (identity.Review, error) {
	q, e := Decode(raw)
	if e != nil {
		return identity.Review{}, e
	}
	a := q.action
	kind := a.str("type")
	r := identity.Review{Kind: "hyperliquid", Title: "Hyperliquid · " + kind, Fields: []identity.Field{}, Warnings: []string{}, Raw: string(q.Action), Digest: "0x" + hex.EncodeToString(q.Digest())}
	add := func(k string, v any) { r.Fields = append(r.Fields, identity.Field{Label: k, Value: fmt.Sprint(v)}) }
	warn := func(s string) { r.Warnings = append(r.Warnings, s) }
	add("Network", q.Network)
	add("Signer", q.Signer)
	add("Nonce", q.Nonce)
	if q.VaultAddress != nil {
		add("Trading account (vault / subaccount)", *q.VaultAddress)
	} else {
		add("Trading account", "Signer account, or the master account if this is an API wallet")
	}
	if q.ExpiresAfter != nil {
		add("Exchange signature deadline", millis(*q.ExpiresAfter))
	} else {
		add("Exchange signature deadline", "Not set")
	}
	warn("Vault returns a signature for the caller to submit. Revocation or the end of this one-shot approval cannot invalidate an issued signature, orders, or permissions already created on Hyperliquid.")
	if q.user != nil {
		warn("This account operation has no signed expiresAfter deadline. Its validity is controlled by Hyperliquid's nonce rules, not the Vault approval countdown.")
	}
	order := func(prefix string, o object) {
		add(prefix+" asset ID", o.get("a"))
		side := "Sell"
		if o.get("b") == true {
			side = "Buy"
		}
		add(prefix+" side", side)
		add(prefix+" size", o.get("s"))
		add(prefix+" limit price", o.get("p"))
		add(prefix+" reduce only", yes(o.get("r")))
		t := o.get("t").(object)
		if l, ok := t.get("limit").(object); ok {
			tif := l.str("tif")
			names := map[string]string{"Alo": "Post only (ALO)", "Ioc": "Immediate or cancel (IOC)", "Gtc": "Good until cancelled (GTC)"}
			add(prefix+" time in force", names[tif])
		} else {
			tr := t.get("trigger").(object)
			which := "Stop loss"
			if tr.str("tpsl") == "tp" {
				which = "Take profit"
			}
			add(prefix+" trigger", which)
			add(prefix+" trigger price", tr.get("triggerPx"))
			add(prefix+" executes as market", yes(tr.get("isMarket")))
		}
		if id := o.get("c"); id != nil {
			add(prefix+" client order ID", id)
		}
	}
	switch kind {
	case "order":
		r.Title = "Place Hyperliquid orders"
		for i, v := range a.get("orders").([]any) {
			order(fmt.Sprintf("Order %d", i+1), v.(object))
		}
		g, _ := json.Marshal(a.get("grouping"))
		add("Grouping", string(g))
		if b, ok := a.get("builder").(object); ok {
			add("Builder", b.get("b"))
			add("Builder fee", units(b.get("f").(uint64), 3)+"% ("+fmt.Sprint(b.get("f"))+" tenths of a basis point)")
			warn("These orders include an additional builder fee.")
		}
	case "modify", "batchModify":
		r.Title = "Replace Hyperliquid orders"
		items := []any{object{{"oid", a.get("oid")}, {"order", a.get("order")}}}
		if kind == "batchModify" {
			items = a.get("modifies").([]any)
		}
		for i, v := range items {
			o := v.(object)
			prefix := fmt.Sprintf("Replacement %d", i+1)
			add(prefix+" original order ID", o.get("oid"))
			order(prefix, o.get("order").(object))
		}
		add("Always place replacement", yes(a.get("a")))
		if a.get("a") == true {
			warn("The replacement may be placed even if cancelling the original order fails.")
		}
	case "cancel", "cancelByCloid":
		r.Title = "Cancel Hyperliquid orders"
		for i, v := range a.get("cancels").([]any) {
			o := v.(object)
			asset, id := o.get("a"), o.get("o")
			if kind == "cancelByCloid" {
				asset, id = o.get("asset"), o.get("cloid")
			}
			add(fmt.Sprintf("Cancel %d asset ID", i+1), asset)
			add(fmt.Sprintf("Cancel %d order ID", i+1), id)
		}
		if a.get("f") == true {
			add("Priority cancel flag", "Enabled; trigger orders cannot be cancelled with this flag")
		}
		warn("Cancelling protective orders can leave a position without its stop loss or take profit.")
	case "updateLeverage":
		r.Title = "Change Hyperliquid leverage"
		add("Asset ID", a.get("asset"))
		mode := "Isolated"
		if a.get("isCross") == true {
			mode = "Cross"
		}
		add("Margin mode", mode)
		add("Leverage", fmt.Sprint(a.get("leverage"))+"×")
		warn("Changing leverage or margin mode can change liquidation risk.")
	case "updateIsolatedMargin":
		r.Title = "Change isolated margin"
		add("Asset ID", a.get("asset"))
		n := a.get("ntli").(int64)
		add("Margin change (micro USDC, signed)", n)
		add("isBuy protocol flag", yes(a.get("isBuy")))
		if n < 0 {
			warn("This removes collateral from the isolated position and can increase liquidation risk.")
		}
	case "scheduleCancel":
		if n := a.get("time"); n != nil {
			r.Title = "Schedule cancellation of all open orders"
			add("Cancellation time", millis(n.(uint64)))
			warn("All open orders for this account will be cancelled at the scheduled time.")
		} else {
			r.Title = "Remove scheduled order cancellation"
			warn("This disables the scheduled cancel-all protection for this account.")
		}
	case "twapOrder":
		r.Title = "Place a time-weighted order"
		o := a.get("twap").(object)
		add("Asset ID", o.get("a"))
		side := "Sell"
		if o.get("b") == true {
			side = "Buy"
		}
		add("Side", side)
		add("Total size", o.get("s"))
		add("Reduce only", yes(o.get("r")))
		add("Execution duration", fmt.Sprint(o.get("m"))+"m")
		add("Randomize timing", yes(o.get("t")))
		warn("A TWAP executes orders over time. The action does not specify a limit price.")
	case "twapCancel":
		r.Title = "Cancel a time-weighted order"
		add("Asset ID", a.get("a"))
		add("TWAP ID", a.get("t"))
	case "noop":
		r.Title = "Invalidate a Hyperliquid nonce"
		warn("Submitting this action consumes its nonce and invalidates any other pending action with that nonce.")
	default:
		labels := map[string]string{"destination": "Destination", "amount": "Amount", "token": "Token identifier", "toPerp": "Move from spot to perpetuals", "sourceDex": "Source venue", "destinationDex": "Destination venue", "fromSubAccount": "Source subaccount", "agentAddress": "Authorized API wallet", "agentName": "API wallet name", "maxFeeRate": "Maximum builder fee", "builder": "Builder address", "validator": "Validator", "wei": "HYPE amount (wei)", "isUndelegate": "Undelegate stake", "user": "Account", "enabled": "DEX abstraction enabled", "abstraction": "Account mode"}
		for _, f := range q.user.fields {
			if f.name == "nonce" || f.name == "time" {
				continue
			}
			v := a.get(f.name)
			if _, ok := v.(bool); ok {
				v = yes(v)
			}
			if v == "" {
				switch f.name {
				case "sourceDex", "destinationDex":
					v = "Default perpetuals venue"
				case "fromSubAccount":
					v = "Signer account"
				case "agentName":
					v = "Unnamed API wallet"
				}
			}
			add(labels[f.name], v)
		}
		switch kind {
		case "usdSend":
			r.Title = "Send USDC within Hyperliquid"
			warn("Transfers USDC to the destination account.")
		case "spotSend":
			r.Title = "Send a spot asset"
			warn("Transfers the specified spot token to the destination account; token symbols and decimals are not independently verified.")
		case "withdraw3":
			r.Title = "Withdraw USDC to Arbitrum"
			warn("Withdraws USDC through Hyperliquid's bridge to the destination. Exchange withdrawal fees apply.")
		case "usdClassTransfer":
			r.Title = "Move USDC between spot and perpetuals"
			if a.get("toPerp") == true {
				add("Direction", "Spot → perpetuals")
			} else {
				add("Direction", "Perpetuals → spot")
			}
		case "sendAsset":
			r.Title = "Transfer an asset between Hyperliquid accounts or venues"
			warn("Transfers the asset to the exact account and venue shown. An empty venue means the default perpetuals venue; spot means the spot balance.")
		case "approveAgent":
			r.Title = "Authorize a Hyperliquid API wallet"
			warn("This grants the named API wallet trading authority that outlives this Vault approval. Revoking Vault access does not revoke the API wallet on Hyperliquid.")
		case "approveBuilderFee":
			r.Title = "Approve Hyperliquid builder fees"
			warn("This grants a persistent builder fee allowance on Hyperliquid. It survives Vault revocation and can apply to future orders.")
		case "tokenDelegate":
			r.Title = "Change HYPE staking delegation"
			warn("This changes staked HYPE. Hyperliquid's staking lock and withdrawal rules apply.")
		case "userDexAbstraction", "userSetAbstraction":
			r.Title = "Change Hyperliquid account mode"
			warn("Account mode changes collateral sharing and liquidation behavior across markets.")
		}
	}
	if q.user == nil && kind != "noop" && kind != "scheduleCancel" {
		warn("Asset IDs are exact protocol identifiers. Symbols and market metadata have not been supplied by the requester or used to replace them.")
	}
	add("Signing digest", r.Digest)
	return r, nil
}
func yes(v any) string {
	if v == true {
		return "Yes"
	}
	return "No"
}
func millis(n uint64) string {
	if n > 253402300799999 {
		return strconv.FormatUint(n, 10) + " ms since Unix epoch"
	}
	return time.UnixMilli(int64(n)).UTC().Format(time.RFC3339) + " (" + strconv.FormatUint(n, 10) + " ms)"
}
func units(n uint64, decimals int) string {
	s := strconv.FormatUint(n, 10)
	for len(s) <= decimals {
		s = "0" + s
	}
	return s[:len(s)-decimals] + "." + s[len(s)-decimals:]
}
