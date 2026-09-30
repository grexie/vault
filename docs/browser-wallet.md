# Chrome Web3 wallet

Grexie Vault works as an injected Ethereum wallet. Chrome holds public addresses and connection state; the private key stays with the Vault browser during approval and the user-controlled signing device. The extension has no seed phrase, password or separate Vault account.

## Install

Use the [Chrome installation page](https://vault.grexie.com/chrome.html) for downloads and the three-step setup.

Install the current `vault` release and pair it with your Vault account and signing device using the [setup guide](setup.md). Then run:

```sh
vault browser-wallet install
vault browser-wallet doctor
```

The command registers Chrome's native-messaging host and installs the bundled extension files. For the source/release ZIP distribution, open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the extension directory printed by `install`. Chrome starts the native host automatically. There is no port, connection token or extra wallet configuration to copy. This distribution is not a Chrome Web Store listing.

The native integration supports Chrome on macOS and Linux. Windows users can use the Vault CLI in WSL, but Chrome's Windows native-host integration is not supplied by the Unix CLI. A browser with a custom user-data directory needs its native host registration in that directory's `NativeMessagingHosts` folder; the ordinary Chrome profile is configured automatically.

Open a Web3 site and select **Grexie Vault** from its wallet selector. In Vault, review the website's origin and select an Ethereum identity. The site receives that address after you approve the connection. The popup shows the connected identity, chain and pending request; **Change identity** asks you to choose again in Vault. Manage or revoke connected sites in Vault → Settings → Connected websites.

```sh
vault browser-wallet status
vault browser-wallet doctor
vault browser-wallet uninstall
```

`serve` is Chrome's native host, not an HTTP server. Starting it manually is normally unnecessary. Uninstall removes native integration and bundled extension files; remove the extension in Chrome to finish. Vault pairing and identities remain intact.

## Connections and approvals

A connection permits one website origin to learn one public Ethereum address. It does not permit signatures, transactions, asset transfers, token allowances or trading delegation. Each signing operation gets a new exact-payload Vault request, notification and passkey approval. No reusable wallet signing lease is created.

- `eth_signTransaction`: signs the reviewed transaction and returns raw bytes. It does not submit.
- `eth_sendTransaction`: the review explicitly says **Approving will sign and submit this transaction**. Approval binds the exact transaction and selected RPC endpoint. Only the local bridge submits it and verifies the returned transaction hash.
- `personal_sign` and `eth_sign`: Ethereum signed-message prefix semantics, matching Geth's `eth_sign`; neither is an arbitrary raw-digest signing escape hatch.
- `eth_signTypedData` / `_v1`: legacy typed array and data-first parameter order, matching MetaMask's v1 convention. Unsupported variants are rejected rather than guessed.
- `_v3` / `_v4`: EIP-712 typed data. Only fields declared in the types are signed. Reviews separate ignored metadata and warn about domain, chain and verifier risks. V4 supports arrays; v3 does not.

Read-only RPC calls use the selected network without signing approval. Ethereum, Base, Optimism, Arbitrum, Polygon, BNB Smart Chain, HyperEVM and Sepolia have initial metadata. Sites can propose arbitrary EVM networks with `wallet_addEthereumChain`; adding and switching networks require review. HTTPS RPC endpoints are required, except literal loopback HTTP endpoints explicitly approved for local development. Adding an already-known chain cannot replace its RPC configuration.

The transaction normalizer supports replay-protected legacy, EIP-2930 and EIP-1559 transactions. It resolves missing nonce, gas and fee fields before review; that normalized transaction is what the signer signs. Unsupported transaction types are rejected. RPC failures after submission may leave an uncertain submission result: check the reviewed transaction's hash before retrying.

## Provider and failures

The extension announces an EIP-6963 provider with `rdns: com.grexie.vault`. It sets `window.ethereum` only when another wallet has not already supplied one. It exposes EIP-1193 `request`, `on` and `removeListener`, connection/account/chain events, permission methods and read-only Ethereum RPC. Unsupported methods return 4200. Rejection/expiry/cancellation returns 4001, missing permission 4100, unavailable Vault 4900 and unknown chain 4902. Invalid parameters use -32602; concurrent requests and rate limits are bounded.

Disconnecting a site empties `eth_accounts` and emits `accountsChanged`. A navigation cancels pending calls; browser or extension shutdown cancels in-flight native work. Existing connection permissions survive restarts, but pending signatures are never automatically replayed. A deleted identity, revoked device, offline signer or unavailable cloud never falls back to another wallet or local key.

## Trust boundary

Chrome supplies the real top-level origin. The worker rejects page-provided origins, cross-extension messages and iframe callers. Native messaging restricts access to the installed Vault extension ID and exposes no localhost network listener. The local process independently checks the signed catalogue, identity, chain, operation, payload and fresh approval. Requests are encrypted for the pinned signing device; the extension cannot choose another signer.

The extension requests `nativeMessaging` and `activeTab`, plus provider content-script matching. It does not request history, inspect DOM contents or collect cookies. A malicious website can imitate its own UI or ask for a dangerous operation; inspect the independent Vault approval. A compromised extension or same-user local process can make requests, but does not gain unattended signatures. Compromising the unlocked approval browser or signing-device environment remains a custody threat.

## Tests

```sh
npm ci
make build check
go test -race ./...
node --test scripts/wallet-provider.test.mjs scripts/wallet-transport.test.mjs
# Start a disposable MongoDB on 127.0.0.1:27028 first:
VAULT_WALLET_ONLY=1 node scripts/vault-browser-smoke.mjs
```

The integration fixture runs a real Chromium extension, real native host, isolated Vault cloud, virtual passkey and a separately paired signing process. Anvil and a generated Solidity token exercise actual transfers, allowances and contract calls using disposable funds. Another EIP-6963 wallet is loaded simultaneously. Cryptographic fixtures are independently generated with the pinned MetaMask signing library; substitution regressions check approved origin, recipient, amount, calldata, chain, identity and signing device.

References: [EIP-1193](https://eips.ethereum.org/EIPS/eip-1193), [EIP-6963](https://eips.ethereum.org/EIPS/eip-6963), [Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging).
