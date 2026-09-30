---
name: grexie-vault
description: Install and configure Grexie Vault, request user-approved SSH, document decryption or transaction signatures, import credentials explicitly, and use approved credentials with familiar tools.
---

# Grexie Vault

Use this skill when the user requests access to an SSH host, encrypted document, named identity or provider credential managed by Grexie Vault. The public instructions are https://vault.grexie.com/SKILL.md and source is https://github.com/grexie/vault.

## Boundaries

Ask for the exact authorized operation and choose a clear session name, identity and justification. Choose the shortest useful duration; 48 hours is the maximum, not the default. Approval is required for private-key use and credential release. A pending, rejected, expired or revoked request is not permission to load a filesystem key, use another identity, reuse a ControlMaster or bypass approval.

Do not print private keys, passwords, connection tokens, passphrases, CVVs or pairing secrets into chat, logs, memory or command arguments. Do not import existing credentials unless the user requested that import. Never submit a payment, broadcast a transaction, deploy, or send a message merely because a credential was approved: authorization for the action is separate.

All identities stay browser-encrypted in the hosted store. Signing keys go only to a separately paired user-controlled signing device. Trust the OS account on that device: same-user processes and root are not isolated security principals. Provider wrappers intentionally give the credential to a child process; revoking Vault access cannot recall copies. Autofill gives values to the selected website and does not submit forms.

## Installation and pairing

Build the public repository with `make build` and install `bin/vault` (Go 1.26.8). Avoid clobbering HashiCorp Vault if installed; use the explicit binary path. Read the repository setup and architecture documents. Cloud configuration uses HTTPS plus a local 32-byte storage-key file and separate MongoDB URI file; never invent or commit deployment secrets.

Run `vault pair --name DEVICE` for a requesting client. The user pastes the code into the app's Connected devices form and approves with a passkey. A trusted signing device has a separate private config: `vault --config AGENT_CONFIG pair --role agent --name SIGNER`, then `vault --config AGENT_CONFIG agent serve`. HTTPS/Tailscale forwards to its loopback port 8792. Use `agent info` for its public ID and `vault agent configure --id ID --url HTTPS_ORIGIN` on requesting clients.

Global options (`--identity`, `--reason`, `--config`, `--agent`, `--agent-url`, `--session`, `--duration`, `--timeout`) precede the command. Request/wait/status/revoke also accept session options after the command. Pairing and passkey enrollment require the human; do not silently substitute local credentials if unavailable.

## SSH and SCP

For ordinary `ssh HOST` and `scp`, generate Vault's native approval rules on each paired requesting device. Use the installed **Vault** binary, not the legacy Remote SSH Agent binary. Each alias needs a distinct session and a meaningful justification:

```sh
umask 077
vault ssh-config --host work-server --hostname server.example.com \
  --identity work --session ssh-work-server \
  --reason 'SSH/SCP access to work-server from this device' --duration 15m \
  > ~/.ssh/vault-agent.conf
```

Add this at the beginning of `~/.ssh/config`, before broader `Host` rules:

```sshconfig
Include ~/.ssh/vault-agent.conf

Host work-server
    User deploy
```

Generate additional aliases into the same included file using `>>`, without duplicating existing aliases. Preserve host, user, port and ProxyJump settings. Remove the old `remote-agent.conf` include when migrating. Remove active private `IdentityFile`/`CertificateFile` entries from all applicable user/system rules: OpenSSH treats these as additive, so `IdentityFile none` alone cannot cancel them. Preserve the original key files and Keychain entries; disable automatic key loading, password fallback, agent forwarding and ControlMaster reuse. The generated rules already set those protections. Inspect `ssh -G HOST` with care: it evaluates the approval hooks too.

A native connection waits for approval, then reuses the matching host lease until it expires or is revoked. The device, identity, signing agent, justification and duration must match; reuse never extends expiry. `vault revoke --session ssh-work-server` closes that lease. Closing SSH does not revoke a shared host lease. A later connection can request fresh approval. The stable host path points to a separate socket for each approved request; the remote signing device communicates over HTTPS.

Reserve generated `ssh-HOST` session names for the native hooks; do not run manual `request`/`wait` concurrently using those same names. For agent work, prefer a scoped task lease below and export its returned `SSH_AUTH_SOCK` before native SSH/SCP. The hooks authenticate that inherited Vault session instead of asking for a second host approval. A stale, revoked, mismatched or legacy inherited socket stops the connection; never unset it to bypass a denial. Native SSH command-line overrides can bypass local configuration, so this is a client workflow, not server-side restriction of the key.

For one command, use the automatic one-shot wrappers:

```sh
vault --identity work --reason 'Read the logs for the deployment failure' ssh node-1 'journalctl -u example -n 50'
vault --identity work --reason 'Copy the reviewed deployment artifact' scp ./artifact.tar node-1:/tmp/artifact.tar
```

Wrappers preserve native arguments and streams. They use a temporary sanitized SSH configuration with only the approved public identity and disable local-key fallback, forwarding and connection reuse. Conflicting `-i`, `-F`, `-A`, `-S` or identity/authentication overrides are refused. Host/jump settings are retained; original SSH configuration is not edited.

For several related commands, request once, wait, bind the returned socket and revoke at completion:

```sh
vault request --session incident-review --identity work --reason 'Investigate the reported deployment failure' --duration 30m --no-wait
vault wait --session incident-review --timeout 10m
vault status --session incident-review
vault revoke --session incident-review
```

`wait` materializes a dedicated socket on the **requesting** machine and writes its path to stdout; `status` does not. Never `eval` the output. Bind both `SSH_AUTH_SOCK` and SSH's `IdentityAgent`. The remote signing device has no SSH socket: requests and replies travel as authenticated encrypted messages over HTTPS. Revoke on completion, cancellation or abandonment; report any unconfirmed revoke. Established SSH connections can remain open after revocation.

## Public identities and age

`vault identity list` and `vault --identity NAME identity lookup --type ssh` read a signed public catalog without approval. `vault --identity NAME --reason TEXT identity create --type ssh|ethereum|bitcoin` asks the user to approve browser key generation. Use explicit `--network` for Bitcoin.

```sh
vault --identity work encrypt --output document.age document.txt
vault --identity work --reason 'Read the document requested by the user' decrypt --output document.txt document.age
```

Encryption is unattended and needs no lease or notification. Inputs/outputs can be `-` for stdin/stdout. Decrypt without `--session` requests one document-bound approval and creates no SSH socket. For repeated approved decryption, request `--access age` and use `decrypt --session NAME`. Do not retain plaintext backups after a verification-only task; delete the downloaded encrypted copy and plaintext when the user requests cleanup.

## Provider credentials

Use `vault --identity NAME gh ...`, `vault aws ...`, `vault docker ...`, or `vault cloudflare ...`. Args, streams and exit codes pass through. The selected tool receives the credential and can retain it. Never claim approval limits provider-side permissions or creates an issuer spending cap.

Import only when explicitly requested: `vault import aws --name NAME --profile PROFILE`, `vault import github --name NAME`, `vault import docker --name NAME --registry HOST`; Cloudflare uses its existing token environment variable or `--stdin`. The user approves encrypted import in the app. Use stdin JSON for manually supplied credentials; keep values out of argv/history. Original configuration is preserved.

Custom providers use `vault provider install FILE.json`, then `vault run PROVIDER -- ARGS` or `vault api PROVIDER METHOD /PATH`. Inspect the local JSON profile and its exact CLI/env/destination scope first. Profiles are data, not executable scripts; basic, bearer, header and query HTTP authentication is supported. Only the approved provider's configured HTTPS origin and paths are accepted; redirects are refused.

## Website logins and cards

`vault browser --browser chrome --cdp http://127.0.0.1:9222` lists targets without reading field values. `vault --identity NAME --reason TEXT autofill --target TARGET --browser chrome` requests approval for the exact origin and document. Use Safari's target IDs from `vault browser --browser safari` and normal macOS automation permission. Navigation while approval is pending invalidates the fill. Do not click Submit or make a purchase without the user's separate authorization.

For payment fields use `--type payment-card` and describe merchant, amount and currency. These describe intent, not an enforced card limit. Cloud cards exclude CVV; `vault --identity NAME card-cvv --stdin` stores it encrypted only on that local device, excluded from cloud/backup.

Explicit Chrome/Safari password migration is site-scoped: `vault import chrome --name NAME --origin https://SITE --username USER`. Run `vault keychain serve` for native macOS import, or supply an official exported `--csv FILE`. Apple may require OS authorization or an export; never bypass it. No cookies or browser sessions are imported.

## Signing and recovery

`vault --identity NAME --reason TEXT sign ethereum < transaction.json` returns signed bytes. Bitcoin `sign bitcoin --network NETWORK` takes and returns base64 PSBT. Neither broadcasts. Review decoded methods and exact recipients, amounts, chain, fees and permissions; an ABI label does not prove contract behavior.

For vanilla Foundry, use `vault ... foundry --rpc-url URL --address ADDRESS --chain-id ID -- cast/forge ... --unlocked`. Only explicit `--broadcast` enables caller-side submission, and the user must authorize the transaction. Never handle real funds during a verification-only task.

Backups are password-encrypted in the browser. Keep the password separately. Do not promise recovery after loss of the passkey and all backups. Shared-owner flows are not released yet; threshold library tests are not permission to use experimental keys for funds. Existing legacy CI grants are documented separately and are not silently migrated to cloud identities.
