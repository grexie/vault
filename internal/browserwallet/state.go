//go:build unix

// Package browserwallet is the user-controlled, keyless Chrome native host.
package browserwallet

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/grexie/vault/internal/vaultwire"
	"golang.org/x/sys/unix"
)

type Site struct {
	ChainID   string    `json:"chainId"`
	RevokedID string    `json:"revokedId,omitempty"`
	LastUsed  time.Time `json:"last_used_at"`
}
type state struct {
	Chains map[string]vaultwire.WalletChain `json:"chains"`
	Sites  map[string]Site                  `json:"sites"`
}
type Store struct{ Path string }

func Builtins() map[string]vaultwire.WalletChain {
	out := map[string]vaultwire.WalletChain{}
	for _, v := range []struct{ id, name, symbol, rpc, explorer string }{{"0x1", "Ethereum", "ETH", "https://ethereum-rpc.publicnode.com", "https://etherscan.io"}, {"0xa", "Optimism", "ETH", "https://mainnet.optimism.io", "https://optimistic.etherscan.io"}, {"0xa4b1", "Arbitrum One", "ETH", "https://arb1.arbitrum.io/rpc", "https://arbiscan.io"}, {"0x2105", "Base", "ETH", "https://mainnet.base.org", "https://basescan.org"}, {"0x89", "Polygon", "POL", "https://polygon-bor-rpc.publicnode.com", "https://polygonscan.com"}, {"0x38", "BNB Smart Chain", "BNB", "https://bsc-rpc.publicnode.com", "https://bscscan.com"}, {"0x3e7", "HyperEVM", "HYPE", "https://rpc.hyperliquid.xyz/evm", "https://hyperevmscan.io"}, {"0xaa36a7", "Sepolia", "ETH", "https://ethereum-sepolia-rpc.publicnode.com", "https://sepolia.etherscan.io"}} {
		out[v.id] = vaultwire.WalletChain{ChainID: v.id, Name: v.name, Currency: vaultwire.WalletCurrency{Name: v.symbol, Symbol: v.symbol, Decimals: 18}, RPCURLs: []string{v.rpc}, ExplorerURLs: []string{v.explorer}}
	}
	return out
}
func (s Store) update(fn func(*state) error) error {
	if e := os.MkdirAll(filepath.Dir(s.Path), 0700); e != nil {
		return e
	}
	fd, e := unix.Open(s.Path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	if e = unix.Flock(fd, unix.LOCK_EX); e != nil {
		return e
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	st := state{Chains: Builtins(), Sites: map[string]Site{}}
	f, e := os.OpenFile(s.Path, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if e == nil {
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 1024*1024 {
			return errors.New("invalid wallet configuration")
		}
		if json.NewDecoder(f).Decode(&st) != nil {
			return errors.New("invalid wallet configuration")
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if st.Chains == nil {
		st.Chains = Builtins()
	}
	if st.Sites == nil {
		st.Sites = map[string]Site{}
	}
	if e = fn(&st); e != nil {
		return e
	}
	b, e := json.Marshal(st)
	if e != nil {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(s.Path), "wallet-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if e = tmp.Chmod(0600); e == nil {
		_, e = tmp.Write(b)
	}
	if e == nil {
		e = tmp.Sync()
	}
	closeErr := tmp.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), s.Path)
}
func (s Store) site(origin string) (Site, error) {
	var v Site
	e := s.update(func(st *state) error {
		v = st.Sites[origin]
		if v.ChainID == "" {
			v.ChainID = "0x1"
		}
		return nil
	})
	return v, e
}
func (s Store) chain(id string) (vaultwire.WalletChain, error) {
	var v vaultwire.WalletChain
	e := s.update(func(st *state) error {
		var ok bool
		v, ok = st.Chains[id]
		if !ok {
			return &Error{Code: 4902, Message: "Unrecognized chain; add it with wallet_addEthereumChain"}
		}
		return v.Validate()
	})
	return v, e
}

// Chains returns locally configured public network metadata for diagnostics.
func (s Store) Chains() ([]vaultwire.WalletChain, error) {
	out := []vaultwire.WalletChain{}
	e := s.update(func(st *state) error {
		for _, c := range st.Chains {
			if e := c.Validate(); e != nil {
				return e
			}
			out = append(out, c)
		}
		return nil
	})
	return out, e
}
