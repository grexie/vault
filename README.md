# Remote SSH Agent

A self-contained Go application that asks for passkey approval on your iPhone or iPad before an agent can use your SSH key. One binary contains the PWA, WebAuthn server, BoltDB metadata store, isolated signing workers, and CLI.

SSH requests require a session name, a justification, and an explicit timed or persistent policy. Approval unlocks a signer on the server; the requesting client creates its dedicated local Unix socket. Expiry, phone revocation, or CLI revocation locks that grant. The CLI only gets a signing capability; it never receives the private key.

## Requirements

- Linux or macOS for the server and CLI.
- A stable HTTPS origin for the PWA. Loopback HTTP is allowed for development.
- A browser and passkey provider supporting **both WebAuthn PRF and largeBlob**. Setup checks these capabilities and fails closed if either is missing.
- Home Screen installation and notification permission on each iPhone/iPad that should receive notifications. Web Push is available for Home Screen web apps on iOS/iPadOS 16.4 and later; a sufficiently recent OS alone does not guarantee PRF/largeBlob support.

**Device-keychain storage is intentional.** The SSH key is unlocked locally with its existing passphrase, encoded as compact standard private parameters, then encrypted with a key derived from WebAuthn PRF and written to the passkey's `largeBlob`. Neither that blob nor the PRF secret is uploaded to the server. Passkey availability, blob size limits, and blob syncing differ between providers. Do not assume all iCloud Keychain or Google Password Manager combinations support this flow. Keep the original key and verify retrieval on a second device before relying on provider sync. There is no silent server-storage fallback.

## Build

```sh
git clone https://github.com/grexie/remote-ssh-agent.git
cd remote-ssh-agent
make build
./bin/remote-ssh-agent version
```

Go 1.26 or newer is required. `make build` uses Go to compile the local key validator to WebAssembly, embeds all web assets, then produces `bin/remote-ssh-agent`. No Node.js, separate frontend server, database service, or runtime asset download is required to run the application. Node is only used by development tests.

Copy the binary to a directory on `PATH` on the server and on each CLI computer. Build on that platform, or cross-compile with `GOOS=linux GOARCH=arm64 go build -o bin/remote-ssh-agent-linux-arm64 ./cmd/remote-ssh-agent` after `make assets`.

## Start the server

Behind an HTTPS reverse proxy:

```sh
remote-ssh-agent serve \
  --origin https://ssh-agent.example.com \
  --listen 127.0.0.1:8787 \
  --data ./data
```

Or terminate TLS in the binary:

```sh
remote-ssh-agent serve --origin https://ssh-agent.example.com \
  --listen :8443 --tls-cert fullchain.pem --tls-key privkey.pem --data ./data
```

Use an origin whose external port matches your URL, e.g. `https://ssh-agent.example.com:8443` when connecting directly to port 8443. Preserve the external `Host` header through a proxy. Forwarded headers are not trusted to change the configured WebAuthn origin.

First startup prints a one-time owner setup token. Open the PWA, enter it, and create a passkey. The token's hash lives in BoltDB and becomes unusable after enrollment. If you lose the token before enrollment, restart with `--reset-setup` to issue a new one. Protect startup logs until enrollment finishes. This is a single-owner application; multiple CLI clients and notification devices belong to that owner.

All persistent server state is in `data/metadata.db` (BoltDB via `bbolt`): WebAuthn public credentials, key name/fingerprint, hashed client credentials, request history, push subscriptions, and VAPID keys. The directory is mode `0700`, the database `0600`. Persistent grant metadata and token hashes survive restart in a locked state. No unlocked signer, decryption key, or SSH private key is restored.

## Set up the phone and tablet

1. On the first device, open **Keychain**, paste the entire existing SSH private key and its current passphrase, and save it. There is no file picker and no filesystem access. A disposable Go/WebAssembly worker validates the pasted key locally.
2. Accept the passkey prompts to derive an encryption key and save the encrypted payload to the credential's largeBlob. Supported imports include encrypted OpenSSH RSA/Ed25519/ECDSA, legacy encrypted PEM RSA/EC, and encrypted PKCS#8 in the algorithms supported by the parser. Wrong passphrases are rejected locally. Hardware-backed non-exportable keys and public keys cannot be pasted as private keys.
3. On both the iPhone and iPad, add the same HTTPS site to the Home Screen, open the installed app, sign in with the same passkey, and tap **Enable notifications** on each device.
4. Verify that the second device can retrieve the saved key with its passkey. If the provider syncs the passkey without its blob, paste the same original key on that device too. Saving/replacing a key revokes open grants.

The server sends a notification to every enrolled device (up to 10). Lock-screen notifications contain no host, justification, key name, or socket path. Open the app to see the full request. Delivery depends on the operating system, network, and notification settings. Requests also appear in the app and remain pollable by the CLI if push fails.

## Pair a CLI

In **CLI clients**, create a pairing token and name the computer. On that computer:

```sh
remote-ssh-agent configure --server https://ssh-agent.example.com --token-stdin
# Paste the pairing token, then press Ctrl-D.
```

The token is stored in a user-only CLI config file. Override its path with `--config PATH` or `REMOTE_SSH_CONFIG`. Tokens can request and revoke their own sessions; they cannot approve access, read the device keychain, or obtain another request's signing capability. Remove a client in the PWA to invalidate it and revoke its sessions.

## Request and revoke

```sh
sock=$(remote-ssh-agent request \
  --session codex-deploy-api \
  --reason 'Deploy the tested API fix and verify service health' \
  --duration 15m) || exit 1

SSH_AUTH_SOCK="$sock" ssh api-host
remote-ssh-agent revoke --session codex-deploy-api
```

The request waits for approval and prints only the socket path to stdout; status messages go to stderr. The allowed duration is 1 second to 48 hours (`--duration 48h` for the maximum) and starts when approval succeeds. Unapproved requests expire after 5 minutes. Each request uses a unique socket, a private directory, and a separate signing process. An existing session name cannot be used for a simultaneous second request by the same client.

For automatic cleanup around one command:

```sh
remote-ssh-agent exec --session codex-read-logs \
  --reason 'Read API logs for the reported error' --duration 10m \
  -- ssh api-host 'journalctl -u api -n 100 --no-pager'
```

For nonblocking agent workflows:

```sh
remote-ssh-agent request --no-wait --session codex-investigate \
  --reason 'Inspect the reported service failure' --duration 10m
remote-ssh-agent status --session codex-investigate
sock=$(remote-ssh-agent wait --session codex-investigate --timeout 5m) || exit 1
```

`request --no-wait` and `status` return public request JSON. `wait` returns a usable socket after approval and exits nonzero on rejection, revocation, timeout, expiry, or network failure. A timeout cancels the request. `status` exits successfully for terminal states as well: read its `status` field. The socket listed for a pending request is reserved but is not yet listening.

## Automatic requests from SSH config

```sh
remote-ssh-agent ssh-config \
  --host approved-api --hostname api.example.com \
  --session codex-api --reason 'Maintain the API service' --duration 15m \
  > ~/.ssh/remote-agent.conf
```

Add `Include ~/.ssh/remote-agent.conf` at the beginning of `~/.ssh/config`. Omit `--hostname` when integrating an existing alias, so its normal `HostName`, `User`, `Port`, `HostKeyAlias`, and `ProxyJump` settings remain in effect. Generate one snippet per alias and append them to the included file.

Now use the native commands normally:

```sh
ssh approved-api
ssh approved-api 'journalctl -u api -n 100 --no-pager'
scp ./report.txt approved-api:/tmp/report.txt
scp -r approved-api:/var/log/api ./logs
```

OpenSSH runs `ensure` while reading the configuration and waits for phone approval before connecting. `IdentityAgent` selects the dedicated socket through a stable session alias. The native programs retain their arguments, stdin, terminal handling, exit codes, SFTP/legacy SCP modes, and jump-host routing. A jump host needs its own snippet and approval, unless both connections inherit an already-approved task socket. Approval failure blocks the connection, including when a different lease is still active under that alias. The snippets disable password fallback, forwarding, and connection multiplexing.

A matching unexpired host lease is reused without extending it. The configured reason is static and the lease lasts until its deadline or explicit `remote-ssh-agent revoke --session codex-api`; closing SSH alone does not revoke a shared host lease. For a concrete task and automatic cleanup, use `remote-ssh-agent exec --session NAME --reason TEXT --duration 10m -- ssh approved-api COMMAND`. Native `ssh`/`scp` then inherit the verified task socket without an additional approval. A manually supplied `SSH_AUTH_SOCK` from `request` works the same way. Ordinary agents are ignored; revoked, expired, age-only, or unverifiable managed sockets fail instead of silently requesting a replacement.

`ssh -G` also evaluates `Match exec` and can trigger approval. Put the include before other rules. OpenSSH command-line settings override configuration, and explicit `IdentityFile` entries are additive: remove private-key fallback entries when requiring approval for all access. This configuration is a client policy, not a restriction on the SSH key's authorized servers or on commands an approved client may run.

## Give this to Codex or Claude Code

Use [SKILL.md](SKILL.md) as the portable agent instructions. Copy it into a `remote-ssh-agent` skill directory in the agent's supported skills location, or explicitly ask the agent to read the repository's `SKILL.md`. It explains task-specific justifications, request/poll/wait, command wrapping, rejection handling, and mandatory end-of-task revocation without assuming your server address or filesystem paths.

## Security and verification

Read [SECURITY.md](SECURITY.md) for boundaries and recovery. Revocation stops new authentication; it cannot disconnect established SSH sessions. During a grant, the server's isolated signer holds the decrypted key in memory and must be trusted. The requesting process must not share that server's privileged OS account.

```sh
make test
make check
```

The browser-to-CLI integration test uses a virtual passkey with real PRF/largeBlob support and a generated encrypted 4096-bit RSA key:

```sh
npm ci
npx playwright install chromium
node scripts/browser-smoke.mjs
```

Playwright is a development-only dependency. This test covers paste validation, phone approval, actual OpenSSH agent signing, polling/waiting, rejection, live socket revocation, expiry, timeout cancellation, the command wrapper, and OpenSSH config evaluation.

Tests use newly generated keys and synthetic WebAuthn credentials. They exercise encrypted key formats, fresh user verification, challenge/origin/replay rejection, independent grants, expiry, revocation, restart behavior, browser envelope encryption, and multi-device notification registration. Physical iPhone/iPad keychain synchronization and real APNs delivery require device acceptance testing; automated tests do not establish those claims.

Protocol references: [WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension), [largeBlob](https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension), [Home Screen Web Push](https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/).

## Sockets on other computers

Pair each client with the Sentinel HTTPS origin. Run `request` on the computer that will run `ssh`, whether that is a Mac mini, a Linux server, or a CI runner. The returned `SSH_AUTH_SOCK` is created **on that client**, not on Sentinel. Each request has its own socket; there is no socket mount or SSH agent forwarding between machines.

```text
ssh on client → client-only Unix socket → authenticated HTTPS → Sentinel → private pipe → signer
```

Sentinel creates no SSH-agent listener for a remote unlock. Each client request also has its own generated Ed25519 proof key. The server requires a fresh signature over every capability-authenticated operation, including its method, URL, body, timestamp and nonce. Copying a request capability alone cannot use that request from another machine. This is possession of a software key, not hardware attestation: copying the complete client state can copy its authority. The local socket and request state are accessible to the same OS user and root.

## Age documents and stdin

Encryption uses the saved **public** SSH recipient, works unattended, and creates no lease or notification:

```sh
remote-ssh-agent encrypt -o report.age report.txt
printf '%s\n' 'example document' | remote-ssh-agent encrypt --armor > example.age
```

Use `-r 'ssh-ed25519 AAAA…'` / `--recipient` or `-R recipients.txt` / `--recipients-file` for explicit public recipients, including offline encryption without pairing. Options can be repeated. Native age public recipients are also accepted for encryption. A saved key from an older app version publishes its public recipient on the next successful approval or key save; until then, supply a public recipient explicitly. Encryption never triggers approval as a fallback.

One-shot decryption asks for approval of that document without creating a reusable lease, local socket, or on-disk request capability:

```sh
remote-ssh-agent decrypt --reason 'Read the deployment report to investigate the failure' \
  -o report.decrypted.txt report.age
cat example.age | remote-ssh-agent decrypt --reason 'Read this supplied example document'
```

The approval is bound to the SHA-256 digest of the canonical age header. The worker releases one document file key, then is destroyed before responding. The approval can be consumed only once and expires one minute after approval if unused. Pending approvals expire after five minutes. Rejection and timeout fail the command.

For repeated decryption, request an explicitly scoped lease:

```sh
remote-ssh-agent request --session review-docs --access age \
  --reason 'Review the encrypted incident documents' --duration 15m
remote-ssh-agent decrypt --session review-docs -o incident.txt incident.age
remote-ssh-agent revoke --session review-docs
```

`--access ssh` is the default. `--access age` cannot authenticate SSH, and an ordinary SSH lease cannot decrypt. `--access ssh,age` must be requested and approved explicitly. The saved key must be RSA or Ed25519 for age decryption, and documents must be encrypted to its matching SSH recipient. ECDSA remains usable for SSH, but not age. This follows the [upstream age SSH recipient format](https://pkg.go.dev/filippo.io/age/agessh).

Only the bounded age header (up to 64 KiB) is sent to Sentinel. Document bodies and plaintext are processed locally. The CLI receives a per-document file key, never the SSH private key. Revocation stops new header decryptions; it cannot recall a released file key or plaintext. Output files are mode `0600`, must not already exist, and are removed on failure. Stdout streams data, so check the exit status: bytes already emitted cannot be retracted after a later integrity error. Put flags before the optional input path; `-` means stdin/stdout.

## Persistent grants for GitHub Actions

A persistent grant authorizes future job connections until you revoke it. It appears alongside normal active requests in the app, with its justification and inactivity timeout. Create it on an already paired trusted computer and approve it once:

```sh
remote-ssh-agent grant create --session github-deploy \
  --reason 'Allow the protected production deployment workflow to authenticate over SSH' \
  --idle-timeout 30d
remote-ssh-agent grant export --session github-deploy \
  --github-repo OWNER/REPO --secret REMOTE_SSH_CONNECTION
```

The export command invokes `gh secret set` with the token on stdin; it does not put the secret in arguments or print it. `--environment production` targets a GitHub environment secret. Authenticate `gh` for the intended repository first. `--token-stdout` is an explicit alternative for piping to a different secret store; do not log it. `grant create --no-wait`, `status --session`, and `wait --session` support asynchronous initial approval. A successful `wait` for a persistent grant emits no socket; jobs create their own sockets with `connect`.

**Inactivity defaults to 30 days**, configurable from `1s` to `365d` with day/hour/minute/second suffixes. Successful new job connections and SSH signatures reset it. Status checks, failed operations, and identity listing do not. On inactivity or server restart, the key locks and existing job sockets close, while the connection token remains valid. The first subsequent `connect` sends a fresh approval notification and waits (five minutes by default, configurable with `--timeout`). Simultaneous waiting jobs share one approval. Denial or timeout fails the waiting jobs and leaves an already-approved persistent grant locked; it does not silently retry. Explicit revocation invalidates the token permanently.

On a runner that has joined the tailnet:

```sh
# REMOTE_SSH_CONNECTION is supplied by GitHub Secrets, never a private SSH key.
printf '%s' "$REMOTE_SSH_CONNECTION" | remote-ssh-agent connect \
  --token-stdin --config "$RUNNER_TEMP/remote-ssh.json" \
  --session "deploy-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" --duration 1h \
  -- sh -c 'ssh -o IdentityAgent="$SSH_AUTH_SOCK" -o IdentityFile=none -o IdentitiesOnly=no -o BatchMode=yes deploy@server.example.com true'
```

`connect` requires a new config path and refuses to overwrite a paired CLI config. It creates a unique local socket and a job-scoped proof key/capability. With a command after `--`, it cleans up that job on exit without revoking the parent grant. Without a command it prints only the socket path; use `revoke --config PATH --session NAME` afterward. Each job has a bounded lifetime of `1s`–`48h` (default `1h`). Job stdin is consumed by the token; pass command input through files. Socket activity does not enforce the job's SSH destinations or commands.

[The example workflow](examples/github-actions.yml) joins Tailscale with `tailscale/github-action@v4`, OIDC client ID/audience, `id-token: write`, and an ephemeral tagged node. Configure a [Tailscale federated identity](https://tailscale.com/docs/features/workload-identity-federation) restricted to the intended repository and branch/environment. Allow that tag to reach Sentinel's HTTPS port and the required SSH destinations in tailnet policy. Keep pinned SSH host keys in `SSH_KNOWN_HOSTS`; never replace verification with `StrictHostKeyChecking=no`. Review and pin action/source revisions for your deployment.

The connection token can create jobs from any client that possesses it and can reach Sentinel; it is not restricted to one physical runner. Keep it in a protected repository/environment and do not expose it to untrusted workflows. Each resulting job capability is separately bound to that runner's generated key. Tailscale OIDC controls network admission; this app controls SSH signing approval. No server SSH private key is distributed to GitHub.

```sh
remote-ssh-agent revoke --session github-deploy
```

Revoking the persistent grant closes every attached job socket and kills its signer. It does not terminate already-authenticated SSH connections. Upgrade all clients with the server: client proof binding requires this version's CLI.
