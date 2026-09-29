---
name: remote-ssh-agent
description: Request temporary SSH access through Remote SSH Agent, wait for phone approval, use its dedicated SSH_AUTH_SOCK, and revoke access when an authorized SSH task ends. Use when this service is configured for the user's SSH access.
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

Do not use `eval`. Each `request` has a distinct actual socket. Progress goes to stderr; successful `request`, `ensure`, and `wait` print only the socket path to stdout. A configured host's explicit `IdentityAgent` overrides `SSH_AUTH_SOCK`; inspect host configuration if the expected identity is not used.

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

The snippet uses `Match originalhost ... exec` to run `ensure` and supplies `IdentityAgent`. Include it before broader SSH rules. Changing the user's SSH configuration is a separate action; do it only when requested. A matching unexpired grant is reused; a fresh grant still needs phone approval. The configured reason is static: use task-specific `request`/`exec` when the intended work differs.

## End access

```sh
remote-ssh-agent revoke --session codex-inspect-api-20260929
```

Revoke on task completion, cancellation, or abandonment, even if time remains. If the server cannot be reached, report that revocation could not be delivered; the grant still has its original deadline. Do not claim revocation succeeded on a failed command.

Revocation prevents new signatures and closes the request's agent socket. It does not terminate an already-authenticated SSH connection or reverse commands already executed. Do not enable agent forwarding unless explicitly required for the task.
