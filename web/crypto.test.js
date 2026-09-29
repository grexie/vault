import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  sealVault,
  openVault,
  sealGrant,
  unb64,
  publicCredential,
} from "./static/crypto.js";
if (!globalThis.crypto)
  Object.defineProperty(globalThis, "crypto", { value: webcrypto });
test("keychain encryption requires the original PRF and credential", async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const payload = {
    key: "synthetic private data",
    passphrase: "test password",
    fingerprint: "test",
  };
  const blob = await sealVault(payload, secret, "credential-a");
  assert.deepEqual(await openVault(blob, secret, "credential-a"), payload);
  await assert.rejects(
    openVault(blob, crypto.getRandomValues(new Uint8Array(32)), "credential-a"),
  );
  await assert.rejects(openVault(blob, secret, "credential-b"));
  await assert.rejects(sealVault(payload, undefined, "credential-a"));
});
test("approval envelope binds the request and fingerprint to its ephemeral recipient", async () => {
  const recipient = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const publicKey = Buffer.from(
    await crypto.subtle.exportKey("raw", recipient.publicKey),
  ).toString("base64");
  const payload = { key: "synthetic", passphrase: "test" };
  const env = await sealGrant(payload, publicKey, "req-a", "fp-a");
  const peer = await crypto.subtle.importKey(
    "raw",
    unb64(env.publicKey),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const secret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peer },
    recipient.privateKey,
    256,
  );
  const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveKey",
  ]);
  const aad = new TextEncoder().encode("remote-ssh-agent/lease/v1:req-a:fp-a");
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: unb64(env.salt), info: aad },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(env.iv), additionalData: aad },
    key,
    unb64(env.ciphertext),
  );
  assert.deepEqual(JSON.parse(new TextDecoder().decode(plain)), payload);
  await assert.rejects(
    crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: unb64(env.iv),
        additionalData: new TextEncoder().encode("other-request"),
      },
      key,
      unb64(env.ciphertext),
    ),
  );
});
test("WebAuthn responses never upload PRF secrets or the encrypted blob", () => {
  const encoded = publicCredential({
    id: "id",
    rawId: new Uint8Array([1]),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: new Uint8Array([1]),
      signature: new Uint8Array([2]),
    },
    getClientExtensionResults: () => ({
      prf: { enabled: true, results: { first: new Uint8Array([9, 9, 9]) } },
      largeBlob: { blob: new Uint8Array([8, 8]), written: true },
    }),
  });
  assert.deepEqual(encoded.clientExtensionResults, {
    prf: { enabled: true },
    largeBlob: { written: true },
  });
});
