# Chrome Web Store publication

The listing copy, disclosures, reviewer instructions and graphics are maintained here. The store upload is the release's `grexie-vault_VERSION_chrome.zip`, containing the built extension files and license. Do not upload this directory as the extension.

Before first publication:

1. Register or select the intended Chrome Web Store publisher, including required developer agreement, registration payment, verification and two-step verification. These decisions belong to the publisher; do not invent identity or legal information.
2. Upload the ZIP as a new draft. Google assigns its store item ID. Open Package → View public key and copy the public key into `extension/manifest.json`'s `key`. Set `internal/browserwallet/native.go`'s `ExtensionID` and `extension/assets/identity.json` to that exact store identity. Update exact known fixtures/references if needed, rebuild and rerun the native boundary/integration checks. Never broaden allowed_origins to a wildcard or trust a page-provided ID.
3. Rebuild the CLI and extension for the same release. Register the new native integration on installed clients. Upload the rebuilt ZIP to the same draft. The generated Chrome ID and native-host ID must match; the build checks this.
4. Fill the listing with listing.md, the PNGs, public privacy URL and reviewer instructions. Select the actual publisher's correct trader status, category and distribution settings. Review all user-data disclosures and certification wording.
5. Submit for review. A submitted or approved draft is not a published listing. Record the actual item URL and status; do not invent a store URL from the development ID.
6. Once the item is published and its listing is accessible, change the installation page's primary button to the real store URL and lead with Add to Chrome. Retain CLI/native setup instructions: a website cannot install the native binary. Verify extension installation, native messaging and an owner-approved wallet flow from the published item.

Current source-build ID before store assignment: kocbneijhmklhomjnmjaopgdpciamann. No Web Store item is claimed by this file.

Official references: https://developer.chrome.com/docs/webstore/publish/ and https://developer.chrome.com/docs/extensions/reference/manifest/key.
