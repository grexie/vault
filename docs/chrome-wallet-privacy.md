# Chrome wallet privacy

Effective 30 September 2026. This notice covers the Grexie Vault Chrome extension and the local Vault wallet bridge. The extension connects Web3 websites to identities in your existing Vault account. It has no separate account, password, seed phrase or private-key store.

## What the extension handles

The extension reads a website's origin (its scheme, hostname and port) to identify the requesting site and enforce connection permissions. Its provider runs on HTTPS pages and supported local development pages. It does not read page text, forms, cookies, saved passwords or Chrome's browsing-history database. Origins for open tabs are processed in memory; this is not a browsing-history collection service.

When you use the wallet, it handles the selected identity's name and public Ethereum address, network settings, wallet requests, request status, signatures and public blockchain responses. Requests can contain personal messages, contract calls, recipients, amounts and other financial information. Only information needed for the wallet operation is passed to the local Vault process. Do not put unrelated sensitive information in a signing request.

The extension does not receive wallet private keys, Vault encryption keys, passkey material, device pairing secrets or signing-device secrets. It does not use advertising or analytics trackers.

## Where information goes

- **Your local Vault process:** Chrome native messaging carries wallet requests between the extension and the installed command. No listening localhost HTTP port is used. The bridge uses your existing Vault pairing.
- **Your Vault service:** The configured cloud service stores and routes connection and signing requests, including their origin, identity, method, network and review payload. The service can read those details during their retention period using its server-held at-rest encryption key. Connection responses also contain an owner-signed public permission record with the selected identity, address and chains; that response is not end-to-end encrypted. Private identity records and key-delivery envelopes have an additional end-to-end encryption layer; the hosted service cannot read their private-key contents. A self-hosted installation uses the service you configure instead of Grexie's service.
- **Your approval and signing devices:** The approval browser displays the request. A passkey approval authorizes the exact operation. Approved private-key data goes encrypted to your separately paired signing device, which returns a signature or signed transaction. It never goes through the extension.
- **Blockchain RPC providers and websites:** The configured RPC provider receives public blockchain queries, which may include your address, and explicitly approved transactions to submit. It sees the connecting computer's IP address. The requesting website receives its approved account address, requested public results and signatures. Submitted blockchain transactions are public and cannot be recalled by deleting Vault data.
- **Infrastructure providers:** HTTPS endpoints and push-delivery services necessarily handle network metadata. Vault push notifications contain a generic request notice, not the signing message or private key. Providers have their own privacy policies.

## Storage and control

Connection grants are held in your encrypted Vault record and distributed as owner-signed public permission data to your paired client. They include the origin, identity, permitted chains and timestamps. The local bridge also stores network settings, current site chains, last-use times and revocation markers in a private filesystem configuration. These public local settings are protected by operating-system file permissions, not by your passkey. Use device encryption and protect your operating-system account.

Pending requests expire at their displayed deadline. Approvals and transient responses expire according to the request lifecycle. Normal APIs stop returning expired records; MongoDB's TTL cleanup removes them asynchronously. Declined and revoked requests retain the original signed review payload for about one hour, while their key-delivery envelope and response are cleared. Connection permissions remain until you revoke them. Operator backups and infrastructure logs may have different retention periods; deleting a live record does not remove a previously created backup or a public blockchain transaction.

You can revoke a website in Vault → Settings → Connected websites, unpair a requesting device, or delete an identity in Vault. Uninstalling the extension stops browser access. `vault browser-wallet uninstall` removes the native integration but intentionally retains your Vault pairing and local wallet settings. To remove those settings as well, delete `wallet-state.json` from your local Vault configuration directory. Keep backups you still need before removing any other Vault data.

## Limited use

Grexie Vault's use of information received through the Chrome extension adheres to the Chrome Web Store User Data Policy, including its Limited Use requirements. Wallet data is used only to provide the wallet functions described here. It is not sold, used for advertising, used to determine creditworthiness, or transferred for unrelated purposes.

For privacy questions, use the [project's support page](https://github.com/grexie/vault/issues). Do not post keys, messages, transaction details or other private information in a public issue. For a security vulnerability, use [private vulnerability reporting](https://github.com/grexie/vault/security/advisories/new).

Read the [architecture](/architecture.html) and [security documentation](https://github.com/grexie/vault/blob/main/SECURITY.md) for the trust boundaries, including the approval browser's delivered code and the operating system on your signing device.
