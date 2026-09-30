# Vault security model

The hosted cloud service, browser, requesting CLI and user-controlled signing device have different trust boundaries. Read the [architecture](docs/vault-architecture.md) and [review with regression evidence](docs/security-review-2026-09-30.md). This preview has received a separate coding-agent security review; it has not received a professional cryptographic audit.

## Storage and authentication

Private identities are encrypted in the browser before upload. A passkey's WebAuthn PRF output unwraps the browser's root key. MongoDB stores that ciphertext under another authenticated-encryption layer, together with encrypted account, session, push and broker records. The deployment encryption key is supplied through a protected local file or container secret; it is never included in source. Opaque HMAC indexes, record versions and expiry times remain visible to the database.

A secure HttpOnly SameSite session cookie survives cloud restarts. The browser's persisted unlock cache is encrypted with a session-specific wrapping secret available only through a cookie-authenticated API. The service does not receive that local cache or the plaintext browser root. Sign-out invalidates the session and clears the cache, secret forms, decrypted previews and worker. Every approval requires a new user-verified passkey assertion bound to its purpose.

The website origin delivers the code that handles decryption. A compromised origin, browser, extension or device can therefore compromise an unlocked vault. PRF and open source do not remove that boundary. Passkey synchronization and PRF support depend on the chosen provider. A new origin requires enrollment; keys are not silently migrated from a different relying-party hostname.

## Device approval and private-key use

Pairing pins the owner's authentication and encryption keys. Device pairing explicitly distinguishes a requesting client from a trusted signing agent. Cryptographic requests must target a separately approved signing agent; the requester cannot supply that agent's receiver. Request type, identity type, duration, payload and receiver are authenticated and checked at both ends.

Only a user-controlled signing agent receives approved SSH or transaction private keys, in memory. The cloud does not run the signing agent. The agent exposes authenticated, encrypted RPC through device-controlled HTTPS. SSH sockets exist only on the requesting machine, with a private directory and mode-0600 socket. The signer does not create a Unix SSH socket. Native SSH/SCP wrappers sanitize inherited identity and agent configuration and supply only the approved public identity.

The cloud and agent recheck participant revocation and live authorization. Network failures, revocation, expiry and signer restart close signing access. SSH leases are bounded to 48 hours. Ethereum/Bitcoin approvals bind one exact transaction and return only the signature or signed transaction. Age one-shot decryption releases one approved document key; the requester then decrypts the payload locally. RSA SSH signing requires SHA-2.

Revocation cannot erase a signature, document key or credential already delivered, undo a transaction, or disconnect an established SSH transport. The owner of the signing device, root, and programs with equivalent local privileges remain trusted. Disabling core dumps and releasing key objects are useful precautions, not a guarantee against swap, privileged debugging or copied process state.

## Credentials and websites

Provider wrappers intentionally deliver the selected credential to an authorized child command. A child or its descendants can retain it. The Docker wrapper uses an in-memory credential helper; its temporary files contain no registry password. Provider-side token invalidation remains the provider's responsibility.

Browser autofill checks the approved origin and document, fills selected visible fields, and does not submit. Website scripts can react to field changes and read values they receive. A displayed merchant or amount is intent, not an enforceable card spending limit. CVV data remains device-local and is excluded from cloud identity backups.

Keychain imports are explicit and site-scoped. They require Vault approval and the operating system's permission; they do not bypass macOS authorization or silently export an entire password store. Browser and OS support must be verified on the actual device.

## Deployment and remaining preview boundaries

API responses are not cached. Request parsing, replay state, rate admission, notification concurrency and active requests are bounded. Only explicitly configured ingress peers may provide a client address; all other forwarding headers are ignored. A trusted proxy must strip untrusted forwarding headers before setting `X-Real-IP`. Keep proxy ranges narrow and update exact peer addresses after an ingress redeployment. Run one cloud replica until admission limits are coordinated across replicas.

Password-encrypted backups contain identity material, not session cookies or device pairing keys. Backups do not create a server recovery path. Losing every usable passkey and backup can mean permanent loss. Shared-owner product ceremonies and recovery are not released yet; do not infer their readiness from CMP/FROST library tests. The pinned threshold library has a documented stale-advisory exception, and the vulnerability scan is not reported as clean.

The retained Remote SSH Agent compatibility service has a different storage/session model and existing persistent CI grants. Its [security model](docs/remote-ssh-agent-security.md) and [guide](docs/remote-ssh-agent.md) remain separate. No old key, pairing token or lease is automatically imported into the cloud app.

Never include private keys, passwords, tokens, cookies, database URIs or decrypted backups in a public issue or security report. Use generated fixtures to reproduce a problem.

## Chrome wallet

The native-messaging host accepts only the fixed installed extension ID and exposes no HTTP/WebSocket listener. Chrome's worker binds calls to the actual top-level sender origin; page-provided origins and extension-private methods are rejected. The Go process independently checks catalogue permissions, the pinned identity and fresh operation-bound approval. Connection shares a public address, not a signing lease. Compromising the extension may produce deceptive requests, but does not bypass the independent PWA's passkey approval or obtain the signing key.

Safe read RPC is an allowlist with deadlines, byte/rate limits, redirect refusal and DNS-pinned public addresses. Private, link-local, reserved and Tailscale/CGNAT targets are refused; literal loopback HTTP requires an explicitly approved development network. RPC metadata is immutable for an existing chain ID. A transaction's approved RPC destination and submission intent are part of its signed request. Signatures are independently verified before return or broadcast.

All signed request envelopes use exact canonical field names and reject unknown fields, duplicate names, case aliases and trailing input before browser review or agent activation. This closes a JSON interpretation mismatch where JavaScript could review `payload` while Go accepted a later `Payload`. Typed-data reviews show only declared signed fields and warn about ignored metadata; v3/v4 and legacy-v1 semantics are kept distinct. A fully received malformed native request fails on its own rather than cancelling other sites' pending approvals.

A signature can authorize effects outside Vault's lifetime: ERC-20 allowances, NFT operators, Hyperliquid API wallets and builder fees may persist until revoked at the destination protocol. Vault revocation cannot withdraw a signature that a caller or site already received. See the [wallet guide](docs/browser-wallet.md) and [Hyperliquid guide](docs/hyperliquid.md).
