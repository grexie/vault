# Independent wallet signing reference fixtures

These fixtures were generated independently of Vault's Go implementation from
the official `@metamask/eth-sig-util` **9.0.0** package. They contain a publicly
known disposable test key. **Never fund it or replace it with a real key.**
Generation performs no wallet connection, account lookup, RPC request, exchange
submission, or other network operation. This is compatibility/security test
work, not a professional cryptographic audit.

## Reference and provenance

- Official source: <https://github.com/MetaMask/eth-sig-util/tree/5a89b8ba61e7e7a9c55f5b1eac6cb236a2a1082d>
- npm version: `@metamask/eth-sig-util@9.0.0`
- Published `gitHead`: `5a89b8ba61e7e7a9c55f5b1eac6cb236a2a1082d`
- Official tarball: <https://registry.npmjs.org/@metamask/eth-sig-util/-/eth-sig-util-9.0.0.tgz>
- Tarball SHA-256: `edbdf9610830fd54d04468417ccfa1ba65b0bf3e57cca3712ddf93271af01216`
- npm integrity: `sha512-iB/iNjA+f+Vl4RlxbWw96UJGJnGG5SP4kZjGlR+e8IC2bTRIzx46r9Xr5mpWgAGeU4G3o3KuXeWRLffhr+JtxA==`
- License: **ISC**, Copyright (c) 2020 MetaMask. Exact upstream bytes are in
  `metamask-eth-sig-util-LICENSE.txt`, SHA-256
  `31ece466097a09d5226c3bbb06543d8f7b6881de291f5f0d4142daaadb30e324`.
- Exact transitive package versions and registry integrity hashes are in
  `package-lock.json`, SHA-256
  `0307801a033e5070f57fb54316842a4511cc75e69568492ace0ab8e4af1d2441`.
- Additional reference source hashes are included in `metamask-vectors.json` and
  checked by the generator before loading the signing code.

The MIT license of Vault does not replace the upstream ISC license. The npm
runtime is an isolated development reference, not a browser or Go dependency.

## Reproduce

Use Node 22 or 24 (generated and checked with Node 24.19.0). Create a disposable
directory outside the repository, copy this directory's `package.json` and
`package-lock.json` there, then run `npm ci --ignore-scripts --no-audit --no-fund`
inside it. Only this dependency-install step needs network access. The lockfile
pins the library and dependencies, and npm verifies registry integrity.

From the repository root:

```sh
node scripts/test-wallet-signatures.mjs /absolute/path/to/disposable-runtime
```

The command recomputes the fixtures and requires byte-for-byte equality. Add
`--write` to regenerate intentionally. The generator takes no key or message
arguments. It blocks Node HTTP, HTTPS, fetch, TCP/TLS connection and DNS entry
points before loading the reference code, and checks that the network blocker
rejects connection and DNS attempts. It verifies all reference signatures by
recovering the public address, including a second recovery directly from each
recorded digest.

## Fixture format and interpretation

`metamask-vectors.json` has three collections:

- `vectors`: **59** ordinary supported messages. Each includes a name, method,
  optional typed-data version, raw `input.data`, canonical `rpcParams`, expected
  digest, signature and recovered address. Personal/Geth signing also records
  byte length and the exact EIP-191 preimage. Structured data records the domain
  and message hashes where applicable.
- `rejections`: **41** inputs that the pinned reference rejects, with the exact
  error. Tests should require rejection, not necessarily duplicate error text.
- `compatibilityCases`: **28** inputs the library accepts but Vault should
  reject or explicitly normalize under a documented rule. These are not demands
  to reproduce permissive behavior. Their expected hashes and signatures make
  the boundary testable. Each has a reason and a conservative `reject`
  recommendation; the Hyperliquid raw-app cases explain a safe projection option.

The inputs cover binary/Unicode/empty messages, legacy primitives and arrays,
nested structs, large decimal and hex integers, domain-only/empty/salted domains,
fixed and nested arrays, missing fields, null structs, unexpected fields,
integer bounds and bool ambiguity. All transactions and addresses are synthetic;
the Hyperliquid timestamps are historical.

## RPC and signing semantics

`personal_sign` uses `[hexBytes, address]`. Geth `eth_sign` uses
`[address, hexBytes]`. Both hash the exact bytes with:

```text
keccak256(0x19 || UTF8("Ethereum Signed Message:\n") || ASCII(decimal byte length) || bytes)
```

This is Geth's documented `TransactionAPI.Sign`/`SignText` behavior, pinned to
[go-ethereum v1.17.6](https://github.com/ethereum/go-ethereum/blob/v1.17.6/internal/ethapi/api.go#L1867-L1890).
It is not signing an arbitrary caller-supplied digest. UTF-8 byte length, embedded
NULs, empty data and 32-byte messages are explicitly covered. Some other wallet
implementations historically used different `eth_sign` behavior; the chosen
Geth semantics should be stated in Vault's documentation.

There is no universal meaning for unversioned `eth_signTypedData` across wallets.
The [MetaMask wallet middleware](https://github.com/MetaMask/eth-json-rpc-middleware/blob/main/src/wallet.ts)
routes it to legacy **V1**, with `[fieldArray, address]`. These fixtures use that
compatibility choice; `eth_signTypedData_v1` is treated as an explicit alias.
The [EIP-712 specification](https://eips.ethereum.org/EIPS/eip-712) itself describes
the unversioned method using the modern structured object and address-first
parameters. Never guess the scheme or swap parameters based on ambiguous input.
Require the explicitly documented shape and reject incompatible calls.

V1 hashes packed field-schema and value hashes, without the EIP-712 domain or
`0x1901` envelope. The two included dynamic-string cases have distinct field
values but exactly the same digest because packed values are ambiguous. A
legacy signature must carry a clear warning that it lacks modern structured
authorization and replay separation.

For the pinned MetaMask implementation, v3 rejects every **present** array but
silently skips missing fields, including missing arrays and missing declared
domain fields. V4 rejects missing primitives/arrays; a missing or null struct
becomes a zero 32-byte value. Both versions ignore undeclared message/domain
fields. V4 also accepts an array with the wrong declared fixed length, and the
reference preserves historically loose signed-integer bounds. A safer wallet
can reject these inputs. It must never show an ignored field as authenticated.

Version 9.0.0 fixes ambiguous bool coercion: real booleans and the exact strings
`"true"`/`"false"` are supported; `0`, `1`, empty/other strings and null are
rejected. Earlier releases could sign the string `"false"` as true. Vault may
further restrict bools to actual JSON booleans. Exact arbitrary-precision
integers must survive parsing; never round them through a JavaScript Number.

## Hyperliquid public application inspection

Read-only inspection of the public application bundles found an injected-wallet
connection through `wallet_requestPermissions`/`eth_requestAccounts`, followed
where required by **`eth_signTypedData_v4`** for `Hyperliquid:AcceptTerms` and
`HyperliquidTransaction:ApproveAgent`. This is static code evidence, not a live
wallet-login test. No application JavaScript was executed and no real account
was queried. The generic dependency also contains `personal_sign` for other
wallet/WalletConnect paths; that alone is not proof the injected login uses it.

The current app's terms type signs `hyperliquidChain` and `time`. ApproveAgent
signs `hyperliquidChain`, `agentAddress`, `agentName` and `nonce`. The domain is
`HyperliquidSignTransaction`, version `1`, zero verifying contract, and the
current wallet chain ID. This differs from the fixed `421614` domain chosen by
the dedicated official Python SDK API signing helpers.

The public app preserves `type` and `signatureChainId` in the message although
they are not declared in those types. Its viem serializer spreads the message
and normalizes address fields, so these extra fields reach the wallet but are
not hashed. The raw-app fixtures document this. Supporting this shape safely
requires projection to the exact signed schema and explicit disclosure of
excluded metadata, or an exact protocol-specific validation of the extras.
Showing all raw fields as signed would be misleading.

The public source inspected on 2026-09-30 is identified by URL and SHA-256 below;
bundles can change and no bundle code is vendored here:

| Public bundle | SHA-256 |
| --- | --- |
| [index-DMtAfrK3.js](https://app.hyperliquid.xyz/assets/index-DMtAfrK3.js) | `863d64b9d735ae206efb224aa108f67b2fb7ed08ba77b1e83da9943bbe8dfd2c` |
| [config-B3kWIW3_.js](https://app.hyperliquid.xyz/assets/config-B3kWIW3_.js) | `d78cb34219c333656cb9845cc3bb1757995a3073983d1b4c823a7b1b68085d6f` |
| [index-CUao1WyN-C4wB_l4q.js](https://app.hyperliquid.xyz/assets/index-CUao1WyN-C4wB_l4q.js) | `0265ded4a57be8df27a45721cc4d03d80079adb54f478490507b9ec09e0bc296` |
| [_esm-C_nWy398.js](https://app.hyperliquid.xyz/assets/_esm-C_nWy398.js) | `f1bc8aabf78c87b9225e1c521f1281b743530b36ca7e4bb2437585dea3a784ea` |

`config` passes its typed objects to export `Dt` in `index-CUao1WyN-C4wB_l4q`
(local function `la`), which requests `eth_signTypedData_v4` for JSON-RPC
accounts. The serializer is export `y` (local `ea`) in `_esm-C_nWy398`.
The approve-agent flow generates an agent key in the application and stores the
approval for submission. Therefore **ApproveAgent is a persistent trading
delegation**, not merely account discovery or sign-in; Vault revocation cannot
undo a signature already issued or revoke the exchange's agent permission.

## Required wallet boundaries beyond signature compatibility

- Bind approval to the actual browser-derived origin, account, selected chain,
  method, exact signed bytes/schema and submission intent. Page-provided labels
  and addresses are untrusted; native messaging must not trust a page-supplied
  origin as proof of which tab called it.
- Account connection exposes a public address, not authority to sign. Recheck
  origin/account permission on each request and after tab navigation, chain or
  account changes. Revoking connection should stop future requests.
- A typed-data domain is an application claim, not verified website ownership.
  Show the actual requesting origin separately. A message can authorize permits,
  transfers or long-lived delegation without submitting a transaction itself.
- Keep exact signed data stable across phone review, device signer and returned
  result. Reject duplicate JSON keys, excessive nesting/size and ambiguous
  numbers. Reject a signature recovered to any address other than the approved
  identity. Do not silently fall back from typed signing to personal/raw signing.
- Transaction submission needs separate exact consent for chain, destination,
  value, calldata, nonce, fee fields and RPC endpoint; a signing permission alone
  does not authorize broadcasting. Already issued signatures may remain usable
  after Vault locks, a device disconnects or the request expires.
