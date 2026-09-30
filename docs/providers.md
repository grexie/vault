# Provider profiles

Built-ins cover AWS, GitHub, Cloudflare and Docker. A custom profile maps named encrypted fields into a specific executable's environment or a restricted HTTPS request. Install with `vault provider install profile.json`; inspect with `vault provider show NAME`. A profile's SHA-256 digest is included in the approval.

```json
{
  "version": 1,
  "name": "example-bearer",
  "label": "Example service",
  "fields": [{"name":"token","label":"API token","secret":true,"required":true}],
  "cli": {"executable":"examplectl","env":{"EXAMPLE_TOKEN":"token"}},
  "http": {
    "origin":"https://api.example.com",
    "pathPrefix":"/v1/",
    "methods":["GET"],
    "auth":{"method":"bearer","token":"token"}
  }
}
```

Profiles must name a command, not a shell fragment or path. Dangerous execution/configuration environment variables are rejected. HTTP destinations are fixed HTTPS origins with explicit methods and path prefixes; redirects are not followed. A profile is local authorization configuration, so review it before installing it. The child executable and local OS account are trusted.

Credentials use `{"provider":"example-bearer","fields":{"token":"..."}}`, supplied over stdin to `vault import example-bearer --name work --stdin`. The CLI encrypts to the pinned owner's key before upload. The owner reviews and saves it in the browser.

Run `vault --identity work run example-bearer -- status`, or `vault --identity work api example-bearer GET /v1/status`. Do not put secrets into the visible request reason or args. The provider's token/IAM permissions remain authoritative. The tool receives the credential and can retain it; Vault cannot revoke copies already exported.

For the exact supported JSON fields for basic, bearer, header and query authentication, see `internal/provider/profile.go` and `vault provider show github`. A provider profile cannot execute scripts or alter system keychain permissions.
