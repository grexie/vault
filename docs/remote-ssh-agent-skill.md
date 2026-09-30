---
name: remote-ssh-agent
description: Use Remote SSH Agent for approved SSH access, age document encryption and decryption, or persistent CI grants when the user has configured this service.
---

# Remote SSH Agent

Use the `remote-ssh-agent` CLI to obtain a request-scoped SSH agent socket. The owner approves on their phone or tablet using a passkey. The CLI never receives the private key.

## Before requesting access

Run `remote-ssh-agent version` to check installation. A human must first deploy the server, create their passkey, paste their SSH key and passphrase into the PWA, and pair this CLI. If the CLI reports that it is unconfigured, ask the user to complete pairing. Do not read their private key, request their key passphrase, or try another credential to bypass this flow.

Choose a unique session name for the current task, a concrete justification describing the intended SSH work, and the shortest practical duration (1 second to 48 hours; `--duration 48h` is the maximum). Names contain only letters, digits, dots, underscores and hyphens, up to 64 characters. Reusing an active grant never extends its expiry.

## Prefer automatic cleanup

For a single authorized command, the wrapper supplies `SSH_AUTH_SOCK` and revokes the grant when the command exits:

```sh
remote-ssh-agent exec \
  --session codex-inspect-api-20260929 \
  --reason 'Read API logs to diagnose the reported 502 errors' \
  --duration 10m -- ssh api-host 'journalctl -u api -n 100 --no-pager'
```

The example command is illustrative. Run only the SSH operation authorized by the user's task. Access approval is not permission to broaden that operation.

For several commands, capture the returned path directly; it is not shell code:

```sh
session=codex-inspect-api-20260929
sock=$(remote-ssh-agent request --session "$session" \
  --reason 'Inspect API logs and service status for the reported outage' \
  --duration 15m) || exit 1
trap 'remote-ssh-agent revoke --session "$session"' EXIT HUP INT TERM
SSH_AUTH_SOCK="$sock" ssh api-host 'systemctl status api --no-pager'
```

Do not use `eval`. Each `request` has a distinct actual socket. Progress goes to stderr; successful `request`, `ensure`, and `wait` print only the socket path to stdout. Current generated SSH snippets verify and inherit an approved `SSH_AUTH_SOCK`, including through jump hosts. Older or unrelated explicit `IdentityAgent` rules can override it; bind `-o IdentityAgent="$sock"` when needed.

## Submit, poll, or wait

```sh
remote-ssh-agent request --no-wait --session codex-inspect-api-20260929 \
  --reason 'Inspect the API service for the reported outage' --duration 15m
remote-ssh-agent status --session codex-inspect-api-20260929
remote-ssh-agent wait --session codex-inspect-api-20260929 --timeout 5m
```

`request --no-wait` and `status` return JSON with the request ID, session, socket path, status, reason, and deadline. A pending socket is not yet listening. `wait` starts the socket after approval, prints its path, and exits successfully. Rejection, revocation, expiry, timeout, and transport failures return a nonzero exit. A wait timeout cancels the request. Prefer `wait` over tight polling; poll `status` every few seconds when other work is continuing.

On rejection, do not create another request automatically. On timeout or connection failure, report the result; retry only when the task still warrants it. If a grant expires during work, obtain a fresh approval before continuing.

## SSH host integration

Generate a scoped configuration snippet:

```sh
remote-ssh-agent ssh-config --host approved-api --hostname api.example.com \
  --session codex-api --reason 'Maintain the API service' --duration 15m
```

Include the snippet before other SSH rules. Omit `--hostname` for an existing alias to preserve its routing. Changing SSH configuration is a separate action; do it only when requested. Once installed, ordinary `ssh HOST` and `scp SOURCE DESTINATION` automatically wait for approval. Jump hosts need their own snippet; native SSH retains its normal options and behavior. `ssh -G` also runs approval checks.

A matching unexpired host grant is reused without extending it, and lasts until expiry or explicit revocation. The configured reason is static: prefer a task-specific `exec` for automatic cleanup or `request` for several commands. Generated snippets verify the inherited task socket with the server and use it without requesting another grant, including in jump-host subprocesses. Other agents are ignored. A revoked, expired, age-only, or unverifiable managed socket fails closed; do not unset it to bypass that result. A failed automatic check blocks the connection even if an older socket still exists. Do not override that failure with alternate keys or a multiplexed connection.

## End access

```sh
remote-ssh-agent revoke --session codex-inspect-api-20260929
```

Revoke on task completion, cancellation, or abandonment, even if time remains. If the server cannot be reached, report that revocation could not be delivered; the grant still has its original deadline. Do not claim revocation succeeded on a failed command.

Revocation prevents new signatures and closes the request's agent socket. It does not terminate an already-authenticated SSH connection or reverse commands already executed. Do not enable agent forwarding unless explicitly required for the task.

## Documents

`encrypt` uses public recipients and must run unattended: no lease, justification, or notification. Use the saved public key by default, or explicit `-r PUBLIC_RECIPIENT` / `-R RECIPIENT_FILE` for offline operation. Never load private key files as a fallback.

```sh
remote-ssh-agent encrypt -o report.age report.txt
remote-ssh-agent decrypt --reason 'Read the encrypted report for the requested investigation' \
  -o report.decrypted.txt report.age
```

One-shot `decrypt --reason` is the default approval path: one document, no reusable lease/socket. For repeated authorized decryption, request `--access age` then `decrypt --session NAME`; revoke that lease afterward. Combined `--access ssh,age` needs explicit approval. Existing SSH leases cannot decrypt. RSA/Ed25519 SSH recipients are supported for decryption; encrypted documents must match the saved key. Read [README.md](README.md#age-documents-and-stdin) for streaming and recipient details. Never log plaintext unless the user requested its contents.

## Persistent CI access

Use only when the user asks to configure ongoing access. Read [README.md](README.md#persistent-grants-for-github-actions) and [the workflow example](examples/github-actions.yml) for setup. Create a grant with a clear workflow justification and `--idle-timeout 30d` (the default), then wait for phone approval. Export to the specified repository with `grant export --session NAME --github-repo OWNER/REPO`; this pipes the connection token directly to `gh secret set`. Do not print or place tokens in arguments, logs, commits, or memory. Scope Tailscale OIDC trust and GitHub environment protections to the intended workflow.

The runner uses `connect --token-stdin --config NEW_PATH --session JOB --duration 30m -- COMMAND`. Each job gets a local socket, capability, and proof key. Command completion revokes that job only. The persistent grant belongs to the user and is not revoked after ordinary jobs; revoke it when the user ends that ongoing authorization. Inactivity and restarts lock the key while retaining the token. The next `connect` requests approval and waits; do not bypass or automatically retry rejection/timeout. Status polling does not keep the key unlocked.

Sentinel uses private pipes to its signer and HTTPS to clients, with no server-side SSH-agent socket for remote unlocks. Only the requesting machine creates a socket. Same-user processes and root can use local sockets; software proof keys are not hardware attestation. The reusable CI connection token intentionally permits future authorized runners, so keep it in GitHub Secrets.
