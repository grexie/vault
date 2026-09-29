# Security model

## Key custody

The PWA validates and decrypts the pasted SSH private key locally, then encrypts its compact private parameters with AES-256-GCM. The original passphrase is discarded. RSA factors and exponent, an Ed25519 seed, or an ECDSA scalar/curve are stored without redundant public/precomputed values, allowing common RSA keys up to 8192 bits to fit the portable 2 KiB largeBlob limit. The encryption key is derived through HKDF-SHA256 from the passkey's WebAuthn PRF output. The credential ID binds the encryption context. This ciphertext is written through WebAuthn largeBlob to the passkey provider. Server APIs receive only the key name/fingerprint and sanitized public WebAuthn responses. PRF results and largeBlob contents are intentionally stripped from those responses.

Keychain syncing and capacity are provider capabilities, not promises made by this application. Retain an independent copy of the original key and its passphrase. There is no server-side decryption recovery key and no enrollment bypass that recovers a lost keychain. A single credential is enrolled; rotation/recovery of that credential requires a planned re-enrollment and re-pairing, not an administrative unlock.

## Temporary signing

Each approval has a single-use WebAuthn challenge bound to the browser session and request ID. User verification is required. The approval UI displays the requesting client, session, justification, key fingerprint, requested duration, and client-supplied socket path. Those descriptions are statements from the paired client; they do not enforce which remote commands it will run.

The browser decrypts its largeBlob only after verification, then creates an ephemeral P-256 ECDH envelope for that request's separate signer process. HKDF and AES-GCM bind the envelope to the request ID and fingerprint. The parent server forwards only encrypted key material. The child verifies the decrypted key fingerprint, permits only identity listing/signing, disallows legacy RSA SHA-1 signatures, and has its own hard expiry timer.

Each request has a random signing capability. Client pairing tokens cannot sign by themselves. The bridge exposes only SSH identity listing/signing through a `0600` Unix socket in a `0700` directory. Adding, exporting, removing, or unlocking keys through the agent protocol is not permitted. No original key file is changed and no system/default SSH agent is loaded.

## Revocation and failure

- Remote revocation is serialized with signing and kills/reaps the key-holding subprocess before returning success.
- The local bridge checks status every second and on every signing request. A terminal status or transport failure closes it. During a network stall, status failure takes up to the HTTP timeout (8 seconds); signing still requires a successful live server check.
- The bridge's local deadline and the signer's separate deadline close access at expiry even when polling is unavailable.
- Server shutdown closes signers; a crash closes their stdin pipes; workers also enforce a hard maximum lifetime. Restart revokes all previously pending/active requests and discards browser sessions, ceremonies, and signing capabilities.
- The `exec` command attempts revocation when its command ends. `request` creates a detached bridge because the calling agent may need several SSH commands. The caller must explicitly revoke when done. A killed caller or undeliverable revoke relies on the original expiry.
- Storage failures close live grants. The pending/active state is never recreated from disk as an unlocked signer.

Revocation cannot recall a signature already delivered, undo a command, disconnect an established SSH transport, or terminate an OpenSSH ControlMaster. An authorized process can open a long-lived connection during its grant. Use SSH-server policy and short-lived certificates if session termination or destination/command restrictions are needed; this application does not claim those capabilities.

## Trust boundaries

The application origin, its delivered JavaScript/Wasm, the passkey provider, server OS, and signer process are trusted. A malicious origin can steal decrypted material during a user-approved ceremony. A privileged or same-UID attacker on the signing server may read its process memory. Run this server separately from untrusted coding agents. The local CLI and any same-UID local process can use its socket/capability until revocation or expiry; Unix permissions do not isolate processes belonging to the same user.

Core dumps are disabled by the executable. Process exit releases key material, and transient byte buffers are cleared where practical. Go and JavaScript do not guarantee complete zeroization of all copies or protection from swap, kernel crash dumps, privileged debugging, or compromised hardware. Configure host protections appropriate to the sensitivity of your keys.

The server enforces an exact origin/Host, secure HttpOnly SameSite cookies on HTTPS, bounded single-use ceremonies, limited request sizes, mandatory justifications, bounded grant duration, no-store API responses, and a restrictive CSP. Push subscriptions use a provider host allowlist and disable redirects to reduce SSRF exposure. Notifications are generic to protect lock-screen privacy.

## Operations

Use a stable dedicated HTTPS origin; changing the relying-party hostname changes which passkeys are usable. Back up the BoltDB file using a consistent filesystem snapshot or while the server is stopped. That backup contains public-key metadata and authentication/push secrets, but cannot restore the SSH key. Protect it with filesystem permissions and encryption appropriate for your server. Never publish the data directory, CLI config, setup token, pairing tokens, or local runtime request files.

Before relying on real keys, verify a generated test key on both target devices: create a passkey, save the keychain blob, enable notifications independently, approve from each device, deny, revoke while the socket is open, let a grant expire, restart the server, and test loss of connectivity. Never interpret a successful mock or virtual-authenticator test as hardware or APNs acceptance.
