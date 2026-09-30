# Set up Vault

## Your phone or tablet

Open https://vault.grexie.com/app/ and create a passkey in your device keychain. The passkey provider must support WebAuthn PRF. iCloud Keychain or a synced compatible passkey provider can make the same passkey available on another device; Vault does not synchronize the SSH key through the password manager itself. The encrypted identity record is stored in Vault's MongoDB, and only PRF-unlocked browser code opens it.

On iPhone and iPad, add the app to the Home Screen, open the installed app, and tap Enable notifications. Do this on both devices. Each installation has its own push subscription. Keep a password-encrypted backup before changing passkey providers. Physical notification behavior depends on OS permission and has to be checked on each device.

Browser sign-in survives server/app restarts through a secure session cookie. The browser stores only an encrypted unlock cache in localStorage; opening it requires a wrapping secret obtained using the current cookie. Signing out invalidates that session, clears the cache, resets sensitive forms, and terminates the browser worker. A fresh passkey verification is required for each approval.

## Import and manage identities

On **Identities**, choose **Import existing** to paste an SSH private key you already use. Select SSH key, give it a name, paste the complete key, and enter its existing passphrase if encrypted. **Encrypt and save identity** opens the key locally and saves a browser-encrypted copy. The key and passphrase are not sent to Grexie in readable form. **Create new** is a separate action that generates a new key; servers will not trust that new public key until you install it there.

Each identity has a **Delete** control with confirmation. Deletion revokes matching active and pending access before saving the encrypted vault, including requests that selected the identity by default. Other open browsers must reload before approving against an older vault version. Keep the original key or an encrypted backup if you need recovery; deletion does not disconnect SSH sessions that have already authenticated or erase copies outside Vault.

In **Settings → Connected devices**, choose **Unpair** to revoke a device and its access. Pairing again requires a new CLI configuration and approval. If you unpair a signing agent, clients need another approved signing agent before they can use their keys.

## Approvals

A device request names the identity, describes its purpose and specifies a duration. Open Requests, review the decoded operation and approve with your passkey. Each requesting client is paired separately from the trusted signing device. Use Revoke to stop new operations. A completed signature or an already authenticated SSH connection cannot be recalled.

## Signing device and client

Build and install the binary as described in README. Pair a requesting client and a separate signing-agent configuration. Configuration directories must be private (0700), and files 0600. Agent pairing authorizes that device to receive approved private keys; compare its name, role and fingerprint in the app.

The signing agent listens on literal loopback only:

```sh
vault --config /path/to/private-agent/config.json pair --role agent --name 'Home signer'
vault --config /path/to/private-agent/config.json agent serve --listen 127.0.0.1:8792
```

Provide HTTPS on that **user-controlled device**. For a Tailscale installation, configure Serve to forward a dedicated HTTPS port to `http://127.0.0.1:8792` using the installed Tailscale CLI's `serve --help`. Keep the port restricted to the intended tailnet devices. Do not expose the agent's plaintext loopback listener directly to a network. Vault also encrypts and authenticates RPC payloads independently of TLS.

`vault agent info` with the agent configuration prints its public ID. On a paired client, run `vault agent configure --id ID --url https://YOUR_AGENT_ORIGIN`. No private SSH key is installed on the client. The agent drops unlocked keys on its own restart; request fresh access afterwards.

The cloud server and signing daemon are separate roles of one binary. Do not run a customer's signing agent on the public Grexie service.

## Native SSH and SCP

Use `vault ssh-config --host ALIAS --identity NAME --session ssh-ALIAS --reason TEXT --duration 15m` on each paired client. Save its output as `~/.ssh/vault-agent.conf` and include that file before broader host rules. Follow the [skill’s complete SSH configuration example](../SKILL.md#ssh-and-scp), including removal of additive private-key fallback and the retired include. Host rules preserve normal SSH arguments and jump hosts; approval failure blocks transport. An explicitly inherited Vault task socket is verified before use. Native host leases expire or can be revoked with `vault revoke --session ssh-ALIAS`.

## Host the cloud service

Use an HTTPS origin with a stable hostname. Passkeys are bound to that hostname and do not migrate from another origin. Put the service behind a TLS reverse proxy and configure the exact external origin.

```sh
umask 077
mkdir -p /secure/vault
vault storage-key --out /secure/vault/storage.key
# Write the MongoDB connection URI into /secure/vault/mongodb.uri through your
# local secret manager. Do not put credentials into shell history or this repo.
vault cloud --origin https://vault.example.com --listen 127.0.0.1:8791 \
  --storage-key-file /secure/vault/storage.key \
  --mongodb-uri-file /secure/vault/mongodb.uri --database grexie_vault
```

The storage key is exactly 32 random bytes. The application never invents a replacement for a lost key. Back it up separately from MongoDB, restrict access to both files, and use authenticated MongoDB/TLS for normal deployments. `--private-mongodb` is an explicit exception for a trusted private overlay or isolated local test; it does not add database authentication or transport encryption.

Every application document is AES-256-GCM encrypted, including account, WebAuthn, session, push and request records. Opaque HMAC routing/index keys, record versions and expiry timestamps remain visible to MongoDB. Identity contents have an additional browser-only encryption layer. MongoDB's own operational metadata, logs, backups and traffic need the operator's usual protections.

The cloud process is a single service replica. Rate limits, active-request admission and serialization of vault changes with approvals are enforced in that process. Distributed admission and a shared transaction/locking mechanism are required before scaling it horizontally. Limit public ingress request sizes and connection rates. When running behind a proxy, set `--trusted-proxies` (or `VAULT_TRUSTED_PROXIES`) to its exact peer IPs or a dedicated ingress-only CIDR. Vault requires one literal `X-Real-IP` from those peers and ignores forwarded headers from other peers. The proxy must discard client-supplied forwarding headers before setting that value. Never trust an unrestricted range or a shared network that arbitrary clients can join. Update this setting if a dynamically addressed proxy changes its peer IP. Browser authentication and device enrollment use separate rate limits.

## Backups and changes

Keep database and deployment-key backups separately. They do not replace a user's password-encrypted identity export. An export excludes session cookies, device pairing keys, active leases and local CVV data. Restore happens locally and previews duplicates/name conflicts before saving. Loss of all decryption material is not recoverable by Grexie.

This release preserves the existing Remote SSH Agent as a compatibility binary. Its host rules, old passkey origin and persistent CI tokens stay separate. Test a new identity and approval before moving production access or revoking older credentials.

## Chrome wallet

The [Chrome installation page](/chrome.html) provides CLI and extension downloads with step-by-step instructions.

Run `vault browser-wallet install` on the paired requesting computer. Load the bundled extension directory printed by the command in Chrome's **Load unpacked** control, then select **Grexie Vault** on a Web3 site. Chrome starts the local native host automatically; there is no port or token to configure. `vault browser-wallet doctor` checks the CLI, native integration, public identity catalogue, configured networks, cloud and signing endpoint.

Choose an Ethereum identity and approve the website connection in Vault. Each signature or transaction asks separately. The popup's **Change identity** opens another connection request; revoke sites in Vault → Settings → Connected websites. See the [complete wallet guide](/browser-wallet.html) for network support, message methods, sign-and-submit consent, installation and recovery. Hyperliquid public balance, positions and orders are available through the [dedicated CLI](/hyperliquid.html).
