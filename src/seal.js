// app-itonami-eigyo — client-side sealing of opportunity payloads.
//
// Threat model (see docs/sfa.md §10): yataverse answers
// GET https://yataverse.com/ipfs/<cid> with the body verbatim (HTTP 200).
// The CID is the only gate — anyone who knows a CID can read the object,
// exactly like IPFS. There is no confidentiality without encryption.
//
// Therefore opportunity (商談) payloads are encrypted client-side BEFORE
// `yataverse put`, and only the ciphertext envelope is stored. The Worker
// serves the ciphertext via the /ipfs proxy; it never sees keys or
// plaintext.
//
// Key management is OUTSIDE this dapp: callers inject a CryptoKey
// (generate one with newKey(), or importKey() a raw 32-byte key held in
// ops tooling). No key material, password, or real opportunity data lives
// in this repo — tests use synthetic payloads only.
//
// Envelope (JSON — this is what `yataverse put` stores):
//   { v: 1, alg: "AES-256-GCM", iv: <b64 12B>, data: <b64 ciphertext> }
// Additional authenticated data binds the purpose (eigyo opportunity v1)
// so a ciphertext cannot be repurposed as another record type.

const AAD = new TextEncoder().encode("eigyo:opportunity:v1");
export const SEAL_ALG = "AES-256-GCM"; // envelope label (JWA name)
const WEBCRYPTO_ALG = "AES-GCM"; // WebCrypto algorithm name (NOT AES-256-GCM)

function b64encode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64decode(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// Ephemeral key for tests / callers that persist keys themselves (e.g.
// keychain, env store — never this repo). Non-extractable.
export async function newKey(cryptoImpl = globalThis.crypto) {
  return cryptoImpl.subtle.generateKey(
    { name: WEBCRYPTO_ALG, length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

// Import a raw 32-byte key held outside the repo (ops tooling).
export async function importKey(rawBytes, cryptoImpl = globalThis.crypto) {
  const bytes = rawBytes instanceof Uint8Array ? rawBytes : new Uint8Array(rawBytes);
  if (bytes.length !== 32) throw new RangeError(`[eigyo/seal] key must be 32 bytes, got ${bytes.length}`);
  return cryptoImpl.subtle.importKey(
    "raw",
    bytes,
    { name: WEBCRYPTO_ALG },
    false,
    ["encrypt", "decrypt"],
  );
}

// Encrypt any JSON-serializable payload (e.g. an opportunity snapshot).
export async function sealPayload(value, key, cryptoImpl = globalThis.crypto) {
  const iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const ciphertext = await cryptoImpl.subtle.encrypt(
    { name: WEBCRYPTO_ALG, iv, additionalData: AAD },
    key,
    new TextEncoder().encode(JSON.stringify(value)),
  );
  return { v: 1, alg: "AES-256-GCM", iv: b64encode(iv), data: b64encode(new Uint8Array(ciphertext)) };
}

// Decrypt an envelope. Wrong key or tampered ciphertext throws
// (AES-GCM authentication failure); no plaintext is ever returned.
export async function openPayload(envelope, key, cryptoImpl = globalThis.crypto) {
  if (!envelope || envelope.v !== 1 || envelope.alg !== "AES-256-GCM") {
    throw new TypeError("[eigyo/seal] unsupported envelope version/algorithm");
  }
  const plaintext = await cryptoImpl.subtle.decrypt(
    { name: WEBCRYPTO_ALG, iv: b64decode(envelope.iv), additionalData: AAD },
    key,
    b64decode(envelope.data),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}
