# Grexie Vault

An encrypted keychain for you and your agents. The website and installable app live at [vault.grexie.com](https://vault.grexie.com). The command is `vault`.

Vault stores browser-encrypted identities, asks for your approval, and sends approved private keys to a signing device you control. Grexie's hosted service stores ciphertext and handles account authentication and notifications. It does not run your signer.

The project is MIT licensed. All application, server, CLI and browser code is here; third-party components retain their [licenses and source notices](THIRD_PARTY_NOTICES.md). This is a preview, not an independently audited custody product. Read the [architecture](docs/vault-architecture.md), [security review](docs/security-review-2026-09-30.md) and [setup guide](docs/setup.md) before using it with valuable credentials.

## Build

Go 1.26.8 is used for native binaries and browser WebAssembly. Node.js 22 or newer builds the TypeScript Chrome extension and runs browser checks. macOS and Linux are supported; Windows can run the CLI inside WSL2. Native macOS Keychain integration requires cgo and the Apple Security framework.

```sh
git clone https://github.com/grexie/vault.git
cd vault
npm ci
make build
install -m 0755 bin/vault "$HOME/.local/bin/vault"
```

`vault` can conflict with HashiCorp Vault's command name. Use the absolute binary path or install this binary as `grexie-vault` if you use both products.

## Connect a client and a signing device

1. Open the app, create a passkey, and unlock your vault. Add identities in the browser. Existing password-encrypted SSH keys are pasted into the form; the browser decrypts them before saving encrypted records.
2. Run `vault pair --name "Work laptop"` on a requesting device. Paste its code into Settings → Connected devices and approve with your passkey.
3. On your signing device, use a **separate configuration**: `vault --config /path/to/private-agent/config.json pair --role agent --name "Home signing device"`. Pairing explicitly identifies this device as trusted to hold approved private keys.
4. Start `vault --config /path/to/private-agent/config.json agent serve`. It listens on `127.0.0.1:8792`. Expose it through HTTPS controlled by that device, such as Tailscale Serve. It creates no SSH socket.
5. Run `vault agent configure --id AGENT_DEVICE_ID --url https://your-signing-device.example` on the requesting client. `agent info` on the signing device prints its public ID.

The signing device must stay online. Its private pairing keys stay on that machine. The cloud and requesting client do not receive its receiver secrets. A dedicated local SSH socket is created on the requesting machine only after approval.

```sh
vault --identity work --reason 'Inspect the failed deployment logs' ssh node-1
vault request --session deploy-review --identity work --reason 'Inspect the failed deployment logs' --duration 30m --no-wait
vault wait --session deploy-review
vault status --session deploy-review
vault revoke --session deploy-review
```

For native `ssh HOST` and `scp`, use `vault ssh-config` and include its generated rules before other SSH settings. The [public skill](SKILL.md#ssh-and-scp) has the exact setup, migration and revocation commands. Native host leases reuse approval until expiry without extending it.

`wait` prints only the SSH socket path to stdout. Bind both `SSH_AUTH_SOCK` and `ssh -o IdentityAgent=...` when using it directly. The `ssh`/`scp` wrappers handle a temporary public-key-only SSH configuration and revoke their own request at exit. An existing SSH connection can outlive revocation.

## Documents and familiar tools

```sh
vault --identity work encrypt --output backup.age backup.tar
vault --identity work --reason 'Verify the requested backup' decrypt --output backup.tar backup.age
vault --identity work gh pr list
vault --identity work aws s3 ls
vault --identity work docker pull registry.example/team/image:tag
vault --identity work cloudflare deploy
```

Encryption uses a signed, encrypted-to-device public-key catalog and needs no approval or lease. Decryption without `--session` asks for one approval bound to the document header, then discards access. An age lease can be requested with `request --access age` and reused with `decrypt --session NAME`.

Credential wrappers pass through arguments, stdin/stdout/stderr and exit status. They release the selected credential to the child process. A tool, its descendants, another process with the same OS privileges, or a website receiving autofill may retain the credential. Revocation cannot invalidate an exported third-party token. Docker uses an in-memory credential helper; its temporary configuration contains no password.

## Import and extend

```sh
vault --reason 'Import the AWS profile I selected' import aws --name work --profile default
vault --reason 'Import my GitHub CLI account' import github --name work
vault import docker --name registry --registry registry.example
vault provider install docs/providers/example-bearer.json
vault --identity example run example-bearer -- status
```

Import is explicit and approval-gated. Existing local credentials remain in place. `import PROVIDER --stdin` accepts credential JSON without putting secrets in command arguments. See [provider profiles](docs/providers.md) for custom CLI environment mappings and bounded HTTPS basic, bearer, header and query authentication.

For an existing Ethereum or Base wallet, use `vault --reason 'Import my existing deployer' import ethereum --name deployer --stdin --address EXPECTED_PUBLIC_ADDRESS` and pipe the hex private key into stdin from its trusted source. The optional `--address` check rejects a different key before upload. Vault derives the public address locally and encrypts the key to the paired owner; approve the identity in the app to save it. Never put the private key in command arguments, shell history or logs. An Ethereum identity works across EVM chains; each signing request specifies its chain ID separately.

Website passwords can be imported one exact HTTPS origin/account at a time from Chrome or Safari through normal macOS authorization, or from a user-exported CSV. `vault keychain serve` caches Chrome's authorized decryption key only in service memory. Apple may still require additional prompts; modern Apple Passwords may require an official export. Vault does not bypass these controls. [Autofill and payment cards](docs/autofill.md) documents the CLI and local-only CVV support.

## Transactions

`vault --identity NAME sign ethereum < transaction.json` returns signed transaction bytes; Bitcoin accepts and returns a base64 PSBT. These commands use the designated signing device and never broadcast. Approval reviews derive from the exact signed bytes. Ethereum reviews include standard ERC20/NFT methods and can fetch verified contract ABIs directly from Sourcify without an API key.

Vanilla Foundry works through the caller-side JSON-RPC adapter:

```sh
vault --identity wallet --reason 'Sign the reviewed contract call' foundry \
  --rpc-url https://your-rpc.example --address 0xYOUR_ADDRESS --chain-id 1 \
  -- cast mktx 0xRECIPIENT --value 0 --unlocked
```

The adapter exposes only the selected address. `--broadcast` explicitly lets the **caller-side adapter** submit transactions for commands such as `cast send --unlocked`; the hosted service and signing daemon never broadcast. Test against Anvil first. Only replay-protected legacy, EIP-2930 and EIP-1559 Ethereum transactions are supported; Bitcoin supports P2PKH, P2WPKH and key-path P2TR with committed outputs.

Threshold CMP/FROST primitives and tests are present, but shared-owner enrollment, recovery and signing are not released in the public app yet. Do not place funds in an experimental shared identity. Imported keys remain single-owner. Strict n-of-n requires every share: if an owner dies without a recoverable share and owner authentication material, access is lost. A policy change cannot recover missing cryptographic material.

## Web3 sites and Hyperliquid

Install the keyless Chrome wallet with `vault browser-wallet install`. Chrome starts its native bridge automatically; there is no localhost port, extension password or second Vault account. Connect a named Ethereum identity in the existing Vault app, then approve each message or transaction there. EIP-6963 discovery coexists with other wallets. Arbitrary EVM networks, EIP-712 v1/v3/v4, account permissions and read-only RPC are supported. `eth_sendTransaction` explicitly approves **sign and submit**; `eth_signTransaction` returns bytes without submitting. See the [installation, compatibility and test guide](docs/browser-wallet.md).

`vault --identity pixi-timoshisa hyperliquid balance`, `positions` and `orders` read public account state without approval. `hyperliquid sign --network mainnet` signs one exact action with fresh approval and returns the exchange envelope; the caller decides whether to submit. See [Hyperliquid commands](docs/hyperliquid.md).

## Self-host and inspect

See [setup](docs/setup.md) for HTTPS, MongoDB, local encryption-key files and backups. The same Go binary serves the app and runs device/client commands. Deployment secrets are excluded from source and images. Database records are independently authenticated and encrypted; identities have a second browser-only encryption layer.

```sh
go test -race ./...
go vet ./...
node --test web/crypto.test.js
# An isolated local MongoDB is required for the real-browser test:
node scripts/vault-browser-smoke.mjs
```

[SKILL.md](SKILL.md) provides instructions for Codex and Claude Code and is also served at `/SKILL.md`.

The original Sentinel Remote SSH Agent remains available through the compatibility binary. Its native SSH rules and persistent CI grants use the previous protocol and storage; [legacy guide](docs/remote-ssh-agent.md). A new passkey origin and explicit device pairing are required for the cloud app. Existing encrypted keys or leases are never silently migrated.
