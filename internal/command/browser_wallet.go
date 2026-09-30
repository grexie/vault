//go:build unix

package command

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	walletext "github.com/grexie/vault/extension"
	"github.com/grexie/vault/internal/browserwallet"
	"github.com/grexie/vault/internal/device"
	"github.com/grexie/vault/internal/vaultwire"
	"github.com/grexie/vault/internal/walletsign"
)

type browserWalletBackend struct {
	options vaultOptions
	client  *device.Client
}

func (b browserWalletBackend) DeviceID() string { return b.client.Config.Device.ID }
func (b browserWalletBackend) Catalog(ctx context.Context) (device.PublicCatalog, error) {
	return b.client.CatalogData(ctx)
}
func (b browserWalletBackend) Control(ctx context.Context, c vaultwire.WalletControl) (vaultwire.WalletControlResult, error) {
	var result vaultwire.WalletControlResult
	if e := c.Validate(); e != nil {
		return result, e
	}
	raw, _ := json.Marshal(c)
	o := b.options
	o.Reason = "Website " + c.Origin + " requests wallet " + c.Operation + " on " + c.Chain.Name
	o.Session = "web3-connect-" + device.RandomID()
	q := requestSpec(o, "wallet-connect", "", "ethereum", raw)
	q.AgentID = b.client.Config.Device.ID
	q.Network = c.Chain.ChainID
	q.Duration = 60
	p, state, e := waitVault(ctx, b.client, o, q)
	if e != nil {
		return result, e
	}
	defer b.client.CloseRequest(p.Request.ID)
	response, e := b.client.Response(p, state)
	if e != nil {
		return result, e
	}
	if _, e = walletsign.StrictJSON(response); e != nil {
		return result, e
	}
	e = json.Unmarshal(response, &result)
	return result, e
}
func (b browserWalletBackend) Sign(ctx context.Context, payload walletsign.Payload) ([]byte, error) {
	raw, e := json.Marshal(payload)
	if e != nil {
		return nil, e
	}
	if _, e = walletsign.Decode(raw); e != nil {
		return nil, e
	}
	o := b.options
	managedSettings(&o, b.client)
	o.Identity = payload.Identity
	o.Reason = payload.Origin + " requests " + payload.Method + " with " + payload.Identity
	if payload.Submit {
		o.Reason += ". Approving will sign and submit this transaction."
	}
	o.Session = "web3-sign-" + device.RandomID()
	q := requestSpec(o, "wallet-sign", payload.Identity, "ethereum", raw)
	q.Network = payload.ChainID
	q.AgentID = o.Agent
	q.Managed = true
	q.Duration = 60
	p, state, e := waitVault(ctx, b.client, o, q)
	if e != nil {
		return nil, e
	}
	defer b.client.CloseRequest(p.Request.ID)
	auth, _, e := b.client.Authorization(p, state)
	if e != nil {
		return nil, e
	}
	if e = walletsign.CheckBinding(raw, payload.Identity, payload.IdentityID, q.Network, auth.PublicKey); e != nil {
		return nil, e
	}
	signed, e := managedRPC(ctx, b.client, o.AgentURL, p, state, "wallet-sign", raw)
	if e != nil {
		return nil, e
	}
	if e = walletsign.Verify(raw, signed, auth.PublicKey); e != nil {
		return nil, e
	}
	return signed, nil
}

func nativeHostDirectory(home string) string {
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts")
	}
	return filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts")
}
func shellLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func browserWalletCommand(ctx context.Context, o vaultOptions, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "help" || args[0] == "-h") {
		fmt.Fprintln(os.Stdout, `Usage: vault browser-wallet install|uninstall|status|serve|doctor

install    Register Chrome native messaging and install the bundled extension.
uninstall  Remove this local integration; keep Vault pairing and identities.
status     Report pairing, public identities, chains and local integration.
doctor     Probe native framing, Chrome registration, cloud and signer access.
serve      Chrome-managed stdin/stdout host; no listening network port.

Uses the existing --config and pinned signing device. No extension secrets.
Connect websites in Vault; every signature and transaction needs new approval.`)
		return nil
	}
	if len(args) == 0 {
		return errors.New("usage: vault browser-wallet install|uninstall|status|serve|doctor")
	}
	config, e := filepath.Abs(o.Config)
	if e != nil {
		return e
	}
	o.Config = config
	home, e := os.UserHomeDir()
	if e != nil {
		return e
	}
	base := filepath.Join(filepath.Dir(config), "browser-wallet")
	host := filepath.Join(nativeHostDirectory(home), browserwallet.HostName+".json")
	switch args[0] {
	case "install":
		if len(args) != 1 {
			return errors.New("install takes no configuration flags; it uses this paired Vault configuration")
		}
		if _, e = loadVault(o); e != nil {
			return e
		}
		exe, e := os.Executable()
		if e != nil {
			return e
		}
		exe, e = filepath.Abs(exe)
		if e != nil {
			return e
		}
		if e = os.MkdirAll(base, 0700); e != nil {
			return e
		}
		extensionDir := filepath.Join(base, "chrome")
		if e = os.MkdirAll(extensionDir, 0700); e != nil {
			return e
		}
		entries, e := fs.ReadDir(walletext.Assets, "dist")
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			b, e := fs.ReadFile(walletext.Assets, "dist/"+entry.Name())
			if e != nil {
				return e
			}
			if e = os.WriteFile(filepath.Join(extensionDir, entry.Name()), b, 0600); e != nil {
				return e
			}
		}
		launcher := filepath.Join(base, "native-host")
		body := "#!/bin/sh\nexec " + shellLiteral(exe) + " --config " + shellLiteral(config) + " browser-wallet serve \"$@\"\n"
		if e = os.WriteFile(launcher, []byte(body), 0700); e != nil {
			return e
		}
		if e = os.MkdirAll(filepath.Dir(host), 0700); e != nil {
			return e
		}
		manifest := map[string]any{"name": browserwallet.HostName, "description": "Grexie Vault Web3 wallet bridge", "path": launcher, "type": "stdio", "allowed_origins": []string{"chrome-extension://" + browserwallet.ExtensionID + "/"}}
		b, _ := json.MarshalIndent(manifest, "", "  ")
		if e = os.WriteFile(host, append(b, '\n'), 0600); e != nil {
			return e
		}
		fmt.Fprintln(os.Stdout, "Chrome native integration installed. Chrome starts Vault automatically when the extension connects.")
		fmt.Fprintln(os.Stdout, "Extension directory:", extensionDir)
		fmt.Fprintln(os.Stdout, "For this source build: open chrome://extensions, enable Developer mode, choose Load unpacked, and select that directory.")
		return nil
	case "uninstall":
		if len(args) != 1 {
			return errors.New("uninstall takes no extra arguments")
		}
		b, e := os.ReadFile(host)
		if e == nil {
			var m struct {
				Path string `json:"path"`
			}
			if json.Unmarshal(b, &m) != nil || m.Path != filepath.Join(base, "native-host") {
				return errors.New("native host is registered to a different configuration; refusing to remove it")
			}
			if e = os.Remove(host); e != nil {
				return e
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		if e = os.RemoveAll(base); e != nil {
			return e
		}
		fmt.Fprintln(os.Stdout, "Native integration removed. Remove Grexie Vault from chrome://extensions to finish. Vault identities and pairing remain intact.")
		return nil
	case "serve":
		if len(args) != 2 || args[1] != "chrome-extension://"+browserwallet.ExtensionID+"/" {
			return errors.New("browser-wallet serve is a Chrome native-messaging host; run browser-wallet install first")
		}
		c, e := loadVault(o)
		if e != nil {
			return e
		}
		o.Timeout = 10 * time.Minute
		b := browserwallet.New(browserWalletBackend{o, c}, browserwallet.Store{Path: filepath.Join(filepath.Dir(config), "wallet-state.json")})
		b.VaultURL = strings.TrimRight(c.Config.Server, "/") + "/app/"
		return browserwallet.Serve(ctx, b, os.Stdin, os.Stdout)
	case "status", "doctor":
		if len(args) != 1 {
			return errors.New("status and doctor take no extra arguments")
		}
		result := map[string]any{"extensionId": browserwallet.ExtensionID, "host": browserwallet.HostName, "transport": "Chrome native messaging (no listening port)", "extensionDirectory": filepath.Join(base, "chrome"), "paired": false, "cloudReachable": false, "signerConfigured": false, "signerReachable": false}
		_, e := os.Stat(host)
		result["chromeIntegrationInstalled"] = e == nil
		exe, _ := os.Executable()
		result["cliInstalled"] = exe != ""
		c, e := loadVault(o)
		if e == nil {
			result["paired"] = true
			ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			catalog, e := c.Catalog(ctx)
			result["cloudReachable"] = e == nil
			names := []string{}
			for _, r := range catalog {
				if r.Type == "ethereum" {
					names = append(names, r.Name)
				}
			}
			result["ethereumIdentities"] = names
			result["signerConfigured"] = c.Config.AgentID != "" && c.Config.AgentURL != ""
			if c.Config.AgentURL != "" {
				client := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
				req, e := http.NewRequestWithContext(ctx, "GET", c.Config.AgentURL+"/", nil)
				if e == nil {
					resp, e := client.Do(req)
					if e == nil {
						resp.Body.Close()
						result["signerReachable"] = true
					}
				}
			}
		}
		result["builtInChains"] = len(browserwallet.Builtins())
		chains, chainErr := (browserwallet.Store{Path: filepath.Join(filepath.Dir(config), "wallet-state.json")}).Chains()
		result["configuredChains"] = chains
		result["chainConfigurationValid"] = chainErr == nil
		var m struct {
			Name    string   `json:"name"`
			Path    string   `json:"path"`
			Type    string   `json:"type"`
			Origins []string `json:"allowed_origins"`
		}
		raw, manifestErr := os.ReadFile(host)
		valid := manifestErr == nil && json.Unmarshal(raw, &m) == nil && m.Name == browserwallet.HostName && m.Type == "stdio" && m.Path == filepath.Join(base, "native-host") && len(m.Origins) == 1 && m.Origins[0] == "chrome-extension://"+browserwallet.ExtensionID+"/"
		result["chromeManifestValid"] = valid
		result["localBridgeResponding"] = false
		if valid {
			probeCtx, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			probe := exec.CommandContext(probeCtx, m.Path, m.Origins[0])
			body := []byte(`{"id":"doctor","origin":"https://vault.grexie.com","method":"eth_chainId","params":[]}`)
			var input bytes.Buffer
			_ = binary.Write(&input, binary.LittleEndian, uint32(len(body)))
			input.Write(body)
			probe.Stdin = &input
			reply, err := probe.Output()
			if err == nil && len(reply) > 4 && int(binary.LittleEndian.Uint32(reply[:4])) == len(reply)-4 {
				var response browserwallet.NativeResponse
				if json.Unmarshal(reply[4:], &response) == nil && response.ID == "doctor" && response.Error == nil {
					if chainID, ok := response.Result.(string); ok {
						_, chainErr := vaultwire.WalletChainID(chainID)
						result["localBridgeResponding"] = chainErr == nil
					}
				}
			}
		}
		result["chromeExtension"] = "Chrome must also have the bundled extension enabled; check its popup for the current site"
		return json.NewEncoder(os.Stdout).Encode(result)
	default:
		return errors.New("unknown browser-wallet command")
	}
}
