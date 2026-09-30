# Local autofill

Vault's CLI can fill a selected Chrome or Safari document after approval. It reads field roles and origin, not existing field values. The approved page is bound to a per-document token, so a reload or navigation while waiting causes the fill to fail. Fields must be visible and unambiguous. The CLI reports field counts and origin; it never prints the filled secrets and never submits the form.

Chrome uses an explicitly configured literal-loopback DevTools endpoint. Use a dedicated automation browser profile, keep that endpoint local, and never expose it to a network. Safari uses the standard Apple Events interface; the OS may require automation permission and Safari's Allow JavaScript from Apple Events setting. Safari has not been physically verified on every supported OS/device.

```sh
vault browser --browser chrome --cdp http://127.0.0.1:9222
vault --identity 'Work login' --reason 'Fill the login on the selected site' \
  autofill --target TAB_ID --browser chrome --cdp http://127.0.0.1:9222
```

The website receives the values and its own code can react to input events. Vault not clicking Submit is not a guarantee that a hostile site will not act. Filling a card is not authorization to purchase.

## Payment cards

The browser can store cardholder, number and expiry in its encrypted cloud vault. CVV is deliberately device-local, excluded from cloud records and exported identity backups:

```sh
vault --identity 'Personal card' card-cvv --stdin
vault --identity 'Personal card' --reason 'Fill the requested checkout; do not submit' \
  autofill --target TAB_ID --type payment-card --merchant 'Example shop' --amount 25 --currency EUR
```

Read the CVV from a local secret input, not a command-line argument. The CLI encrypts it to this device's own key. A merchant/amount in the request describes the caller's intent; it is not a provider-enforced spending limit. Issuer controls and the user's purchase authorization still apply.

## Import a saved login

Native import is explicit and restricted to one HTTPS origin and account. The first approval authorizes the read; a second reviews the resulting account before encrypted cloud save. No browser cookies, session tokens or bulk keychain database exports are performed.

```sh
vault keychain serve
vault --reason 'Import the selected account' import chrome --name 'Work login' \
  --origin https://example.com --username user@example.com
```

Use `safari` instead of `chrome` for Safari. Modern Apple Passwords can require an official export; provide it with `--csv FILE`. The original export is preserved, so delete it yourself after confirming migration if desired. Chrome's OS-authorized safe-storage key is cached only in the service process until it exits. Apple Keychain item policies may still require additional prompts; Vault does not weaken those policies.
