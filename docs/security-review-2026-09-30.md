# Security review — 30 September 2026

This is an independent review by a separate coding agent, requested before publication. It is not a professional security audit, a cryptographic proof, or a guarantee that the software has no vulnerabilities. The implementation was changing during the review; findings below distinguish verified fixes from outstanding release work.

The review covered the hosted account and broker service, encrypted MongoDB storage, passkey and session handling, browser approval code, device protocol and agent, provider integrations, browser autofill, Keychain import, transaction signing, backups, and threshold-signature wrapper. Tests used generated keys and isolated local servers. No production credentials, actual purchases, transaction broadcasts, or production service restarts were used.

## Findings and remediation

| Finding | Impact | Remediation and verification |
| --- | --- | --- |
| Request kind and identity type could disagree. | A malicious paired client could show one class of approval while requesting a different secret, such as an SSH key under an Ethereum transaction review. | A shared request validator now binds each operation to permitted identity types. The server and browser worker apply it. Negative wire and broker tests reject mismatched classes and unmanaged cryptographic operations. |
| Cryptographic signing originally exported the full private key to the requesting CLI. | Approval of one transaction did not constrain a modified requester to that transaction. | SSH, age, Ethereum and Bitcoin require a managed signing device. Pairing distinguishes requesting clients from explicitly approved signing agents; a managed requester cannot supply the agent's receiver. The agent checks the owner signature and exact transaction payload, permits a transaction once, and returns an encrypted, signed result. A modified transaction and repeated transaction are rejected in regression tests. The signing device's operating system remains trusted. |
| Revoking a requesting device did not invalidate an existing remote-agent approval. | A revoked requester could continue sending direct RPCs to another device's signer until expiry. | Status, inbox and approval paths recheck both participants. The agent checks live approval state before an operation and drops its lease on failure. Tests revoke either participant and verify further access and approvals fail; a separate RPC test verifies the local keyring is discarded. |
| Browser and Go Ethereum JSON parsers interpreted case variants differently. | The ABI review could describe lowercase `data` while Go selected a later `Data` member for signing. | Transaction parsing rejects duplicate, case-variant and noncanonical top-level members. Tests include `data`/`Data`, repeated `to`, escaped duplicate member names, and conflicting `data`/`input`. |
| Docker credentials were written to a temporary configuration file. | An abrupt process exit could leave reusable credentials behind. | A temporary Docker credential helper now obtains one registry credential from process memory through a private Unix socket and capability. The configuration contains only helper metadata. A fixture test checks all regular files for the password, username, capability and encoded auth value, rejects a different registry or capability, and verifies cancellation stops access. |
| Session locking left draft secrets and worker state alive. | Logout or expiry could leave private-key form values, a decrypted restore preview, or pending work in the browser. | A central lock path closes dialogs, clears forms and references, terminates the worker, rejects pending work and invalidates stale asynchronous responses. A subsequent browser regression verified that session expiry clears unsaved key/passphrase drafts, decrypted restore previews, open dialogs and the encrypted unlock cache. Sign-out and re-login also passed. |
| The new SSH agent path did not enforce its stated RSA signature policy. | RSA signing with the legacy SHA-1 algorithm remained possible. | The agent parses the framed request and requires exactly an RSA SHA-2 flag. Generated-key tests reject legacy/unknown flags and independently verify SHA-256 and SHA-512 signatures. |
| Request submission and notification work were unbounded. | One account could accumulate large pending requests and start excessive push tasks. | Request admission is rate limited, active requests are capped, and push work is bounded and coalesced. The initial custom rate-key implementation incorrectly collapsed unrelated devices into one bucket; this was corrected. An isolation regression verifies one account cannot exhaust another's request allowance. The rate map now has a hard 10,000-key bound; a capacity regression verifies refusal of new keys, continued access for existing keys and reclamation of expired entries. |
| Authentication and enrollment limits used the reverse proxy's address. | One external client could exhaust the shared ingress quota and prevent unrelated clients from signing in or pairing. | Forwarded addresses are accepted only from explicitly configured proxy peers. Trusted peers must provide exactly one literal `X-Real-IP`; untrusted forwarding headers are ignored. Tests cover independent proxied clients, spoofed headers, duplicate and malformed values, canonical IPv4/IPv6 identity, invalid/default-route CIDRs, separate authentication/enrollment quotas, and refusal before replay or device records are written. Enrollment is counted once. |
| Unsupported GET requests consumed the authentication quota. | A malicious website could cause cross-site GETs from a victim's browser and exhaust the victim's allowance before the server rejected the unsupported method. | The authentication limiter now applies only to POST requests, after the same-origin check. A regression reproduces the former denial of service and verifies that unsupported cross-site GETs no longer prevent a legitimate passkey request. |
| `IdentityFile=none` did not remove private-key files from an existing SSH configuration. | Native SSH/SCP could fall back to a local private key despite selecting the Vault socket. | The wrapper now prepares a private temporary configuration, removes inherited key and agent settings, and supplies only the owner-approved public identity. A no-network `ssh -G` test confirms the resolved identity and socket while preserving host, user, port and jump settings. Additional regressions reject explicit, grouped and post-destination authentication overrides and a leading wrapper `--`; remote command arguments remain intact. |

## Verification performed by the reviewer

The review added `security_review_test.go` files under `internal/cloud`, `internal/command`, `internal/deviceagent`, `internal/identity`, `internal/provider`, and `internal/vaultwire`, plus `internal/cloud/security_review_proxy_test.go`. They exercise authentication and replay boundaries, secret-class substitution, signing-device roles, receiver ownership, participant revocation, transaction binding, RSA signature policy, credential-helper persistence, request-limit isolation, proxy identity, bounded rate storage, cross-site quota abuse, and native SSH configuration. Focused tests passed with the Go race detector, including a full rerun of cloud security regressions after the proxy changes. Existing cloud, storage, provider, Keychain, identity and Foundry tests were also run.

A redacted Gitleaks scan of the intended working-tree source and embedded assets found no leaks: the snapshot contained 187 files and the scanner examined approximately 888 KB of text. Ignored build outputs, local tooling and the unrelated `wasm_exec 2.js` file were excluded; embedded binary assets were present in the snapshot but are not equivalent to text source scanning. A subsequent scan of the exact staged release snapshot covered 261 files and approximately 1.15 MB of text, also with zero findings. Repeat the scan after further source changes. A clean secret scan is not proof that every possible secret format is detectable.

Physical iPhone/iPad push delivery, macOS Safari/Password authorization, the public production deployment, and complete threshold-key ceremonies are outside the completed reviewer checks. A library signature test does not establish that owner invitations, recovery or the complete shared-key product flow works.

## Subsequent release checks

The main agent ran the full Go race suite, `go vet`, JavaScript syntax and crypto tests, and browser end-to-end checks with generated credentials and an isolated MongoDB. The new cloud flow passed WebAuthn PRF registration/unlock, device-role pairing, unattended age encryption, one-shot decryption, requester-only SSH sockets and revocation, exact Ethereum transaction signing, approved/denied provider access, browser autofill/navigation binding, cookie persistence across a server restart, password backup restore into another account, and expiry/sign-out cleanup. The retained legacy browser suite also passed native SSH/SCP, age and persistent-grant checks.

These checks do not expand the separate review into a professional audit. Public deployment and physical device verification are distinct follow-up checks.

## Dependency scanner results and evidence

The official `govulncheck` v1.8.0 scan reported a Taurus entry as reachable and an OpenPGP entry at module level. The scan must not be represented as clean. Both entries were investigated rather than silently suppressed.

### GO-2024-3288 / GHSA-7f6p-phw2-8253

The [Go database entry](https://pkg.go.dev/vuln/GO-2024-3288) is marked unreviewed and lists every version with no known fix. The [upstream advisory](https://github.com/taurushq-io/multi-party-sig/security/advisories/GHSA-7f6p-phw2-8253) has newer information: it identifies versions through `v0.6.0-alpha-2021-09-21` as affected and `v0.7.0-alpha-2025-01-28` as patched. The issues concern the DKLS oblivious-transfer implementation. [Upstream PR #119](https://github.com/taurushq-io/multi-party-sig/pull/119) contains the OT checking correction.

Vault pins the exact patched release. The local Go module metadata was checked against the [upstream release](https://github.com/taurushq-io/multi-party-sig/releases/tag/v0.7.0-alpha-2025-01-28):

```text
module: github.com/taurusgroup/multi-party-sig
version: v0.7.0-alpha-2025-01-28
origin commit: 87149255f941d4cfbf09aad2eb239517323aa3ad
module checksum: h1:rbyJpV3kH/aMxG7gUQ5ynveAEXuPiIG136Ld3HGNV7I=
```

The installed source contains the corrected field-element check. In addition, `go list -deps ./internal/threshold` resolves the CMP and FROST implementations and does not import the affected `internal/ot` or `protocols/doerner` paths. These facts support a documented stale-advisory exception for this release, not a general assertion that the threshold library is audited or safe under every use. Re-evaluate the exception if the module version or imported protocols change.

### GO-2026-5932

This entry concerns the unmaintained `golang.org/x/crypto/openpgp` packages. The scanner reports it only at module level: Vault requires `golang.org/x/crypto` for other primitives but does not import those OpenPGP packages. It is not a reachable OpenPGP path in the reviewed application.

## Trust boundaries that remain

- The cloud stores encrypted identity data and encrypted grants. The live website still delivers the browser code, so compromise of that code's delivery origin can compromise an unlocked browser. Source availability does not eliminate this web-delivery trust boundary.
- The separately paired signing device receives private keys in memory. Its administrator, root, and other code with equivalent local privileges are within the trusted boundary. Encryption and signed RPCs protect the network; they do not isolate a compromised operating system.
- Configured proxy peers control the client identity used for IP quotas. They must sanitize incoming forwarding headers. Default-route CIDRs are rejected, but explicitly configured narrower ranges are still an operator trust decision; do not use a network open to arbitrary clients. Exact proxy task addresses require configuration updates when those tasks move. The review tested this boundary with isolated requests, not the deployed ingress configuration.
- Provider command wrappers intentionally release a credential to the selected child process. Revocation stops later Vault access and the running wrapper, but cannot invalidate a copied provider token or undo actions already taken. Provider-side token rotation is separate.
- Autofill releases selected values to the approved website. The CLI does not submit a form, but website scripts control their own response to input events. A caller-supplied merchant or amount is descriptive intent, not a payment-card spending limit.
- Revocation cannot undo a completed signature or disconnect an already authenticated SSH session. Crypto lease expiry is checked on the agent, and continued use also depends on live approval status.
- Password backup security depends on its password. A shared-key identity backup contains one share and is not, by itself, a complete owner-recovery mechanism. Loss of an owner in an n-of-n design can prevent future signing unless recovery was explicitly designed and provisioned beforehand.
