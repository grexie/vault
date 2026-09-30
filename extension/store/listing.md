# Chrome Web Store listing

Name: Grexie Vault

Summary: Your Vault identities in Web3. Private keys stay on your signing device.

Language: English

Suggested category: Tools (choose the closest current dashboard category)

Homepage: https://vault.grexie.com/chrome.html

Support: https://github.com/grexie/vault/issues

Privacy: https://vault.grexie.com/chrome-wallet-privacy.html

## Description

Grexie Vault connects Web3 websites to your existing Vault identities. Choose your wallet, review the request on your Vault device, and continue on the website.

The extension holds no wallet private keys. It connects to the Vault command on your computer and uses your own signing device. There is no extension password, seed phrase or separate wallet account.

Connect an Ethereum identity to a website. Read public blockchain information. Review and approve messages, typed data and transactions in Vault. Switch identities from the small toolbar popup, and manage connected websites in Vault Settings.

Vault works alongside other installed wallets through EIP-6963. It supports Ethereum, Base and other EVM networks, with approval when a website asks to add or switch networks. Every signature and transaction needs its own approval; connecting a wallet does not grant permission to spend or sign later.

Setup requires the Grexie Vault command on macOS or Linux, a paired Vault account, and your own signing device. Run `vault browser-wallet install` to register Chrome's native integration. Chrome starts the bridge automatically. See the installation page for downloads and setup instructions.

To provide these wallet functions, Vault processes website origins, selected public account names and addresses, and the wallet requests you make. Requests may include messages and transaction details. They pass through the local command and your configured Vault approval service. Read the privacy notice for storage, RPC providers and data controls. The extension does not read page text, forms, cookies or saved passwords, and includes no advertising or analytics trackers.

The complete implementation is open source and MIT licensed at github.com/grexie/vault.

## Assets

- Icon: ../dist/icon-128.png (128 × 128, transparent)
- Screenshot 1: wallet-connected.png (1280 × 800)
- Screenshot 2: wallet-approval.png (1280 × 800)
- Small promotional tile: small-promo.png (440 × 280)

Screenshots show actual test-interface captures with disposable identities. They do not contain production account data.

## Permission explanations

Single purpose: Connect Web3 websites to existing Grexie Vault Ethereum identities and carry each user-approved wallet operation through the user's locally installed Vault command and separately paired signing device.

nativeMessaging: Communicates with the com.grexie.vault native host installed by `vault browser-wallet install`. The local host uses existing pairing, verifies site/identity/network permissions, submits exact approval requests, and communicates with the user's pinned signing device. It returns public data, signatures and transaction results, never private keys. No localhost HTTP listener is opened.

activeTab: Identifies the website for the user-opened wallet popup so the popup can display that site's connected account, network and pending approval. It does not read page content or cookies.

Content-script matching on HTTPS websites and literal local-development origins: Supplies the EIP-1193/EIP-6963 wallet provider to ordinary dApps, without collecting page text. Requests are bound to the top-level origin supplied by Chrome. A site receives an account only after connection approval. Local-development matching supports developers testing contracts on loopback networks.

Remote code: No. All JavaScript executed by the extension is included in the package. The native Vault command is installed separately by the user; the extension neither downloads nor executes remotely hosted JavaScript or WebAssembly. The separate Vault PWA is an ordinary website used for approval.

## Data disclosures

Dashboard selections: personally identifiable information (identity labels); financial and payment information (public wallet addresses, balances, transaction requests/results); authentication information (signature results used for login); web history (connected/requesting origins); website content (messages/typed data submitted for signing); user activity (wallet operations, statuses and last-use timestamps); location (source IP/network metadata handled by the configured service and RPC providers).

These are handled for the wallet's single purpose even if processed only locally. Location does not mean GPS or geographic tracking. User activity does not mean recording unrelated network traffic, clicks, mouse movements, scrolling or keystrokes. There is no health-record or email/chat/SMS collection feature. Do not claim that the extension handles no user data.

No sale of user data; no advertising; no unrelated use or transfer; no creditworthiness or lending use. The public privacy notice describes actual processing and storage. Confirm current dashboard wording against that notice before certification.
