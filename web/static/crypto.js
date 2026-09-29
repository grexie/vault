const encoder = new TextEncoder();
export function b64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
export function unb64(value) {
  return Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    (c) => c.charCodeAt(0),
  );
}
export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function optionsFromJSON(options) {
  const p = structuredClone(options.publicKey);
  p.challenge = unb64(p.challenge);
  if (p.user) p.user.id = unb64(p.user.id);
  for (const list of ["allowCredentials", "excludeCredentials"])
    if (p[list]) p[list] = p[list].map((c) => ({ ...c, id: unb64(c.id) }));
  if (p.extensions?.prf?.eval)
    p.extensions.prf.eval.first = unb64(p.extensions.prf.eval.first);
  if (p.extensions?.largeBlob?.write)
    p.extensions.largeBlob.write = unb64(p.extensions.largeBlob.write);
  return p;
}
// Never serialize PRF results or the largeBlob: both must remain on the phone.
export function publicCredential(c) {
  const ext = c.getClientExtensionResults();
  const safe = {};
  if (ext.prf && typeof ext.prf.enabled === "boolean")
    safe.prf = { enabled: ext.prf.enabled };
  if (ext.largeBlob) {
    safe.largeBlob = {};
    for (const k of ["supported", "written"])
      if (typeof ext.largeBlob[k] === "boolean")
        safe.largeBlob[k] = ext.largeBlob[k];
  }
  const response = { clientDataJSON: b64url(c.response.clientDataJSON) };
  for (const key of [
    "attestationObject",
    "authenticatorData",
    "signature",
    "userHandle",
  ])
    if (c.response[key]) response[key] = b64url(c.response[key]);
  if (c.response.getTransports)
    response.transports = c.response.getTransports();
  return {
    id: c.id,
    rawId: b64url(c.rawId),
    type: c.type,
    authenticatorAttachment: c.authenticatorAttachment,
    response,
    clientExtensionResults: safe,
  };
}
async function wrappingKey(prf, credentialID) {
  if (!prf || prf.byteLength !== 32)
    throw new Error(
      "This passkey did not provide PRF encryption. Try a supported passkey provider.",
    );
  const material = await crypto.subtle.importKey("raw", prf, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(credentialID),
      info: encoder.encode("remote-ssh-agent/keychain/v1"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
export async function sealVault(payload, prf, id) {
  const key = await wrappingKey(prf, id),
    iv = crypto.getRandomValues(new Uint8Array(12)),
    data = encoder.encode(JSON.stringify(payload));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: encoder.encode(id) },
      key,
      data,
    );
    const blob = new Uint8Array(13 + ciphertext.byteLength);
    blob[0] = 1;
    blob.set(iv, 1);
    blob.set(new Uint8Array(ciphertext), 13);
    if (blob.length > 2048)
      throw new Error(
        "This key exceeds the portable 2 KB keychain storage limit. No server copy was made.",
      );
    return blob;
  } finally {
    data.fill(0);
  }
}
export async function openVault(blob, prf, id) {
  if (!blob || blob.byteLength === 0)
    throw new Error(
      "No SSH key was found with this passkey on this device. Paste and save your key here first.",
    );
  const bytes = new Uint8Array(blob);
  if (bytes[0] !== 1 || bytes.length < 30)
    throw new Error("Unsupported keychain format");
  const key = await wrappingKey(prf, id),
    plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: bytes.slice(1, 13),
        additionalData: encoder.encode(id),
      },
      key,
      bytes.slice(13),
    );
  try {
    return JSON.parse(new TextDecoder().decode(plain));
  } finally {
    new Uint8Array(plain).fill(0);
  }
}
export async function sealGrant(payload, recipient, id, fingerprint) {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );
  const pub = await crypto.subtle.importKey(
    "raw",
    unb64(recipient),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const secret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: pub },
    pair.privateKey,
    256,
  );
  const salt = crypto.getRandomValues(new Uint8Array(32)),
    iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(
    "remote-ssh-agent/lease/v1:" + id + ":" + fingerprint,
  );
  const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveKey",
  ]);
  new Uint8Array(secret).fill(0);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: aad },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const plain = encoder.encode(JSON.stringify(payload));
  try {
    return {
      publicKey: b64(await crypto.subtle.exportKey("raw", pair.publicKey)),
      salt: b64(salt),
      iv: b64(iv),
      ciphertext: b64(
        await crypto.subtle.encrypt(
          { name: "AES-GCM", iv, additionalData: aad },
          key,
          plain,
        ),
      ),
    };
  } finally {
    plain.fill(0);
  }
}
