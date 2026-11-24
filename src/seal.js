// app-itonami-eigyo — client-side sealing of opportunity payloads.
//
// Threat model (see docs/sfa.md §10 and §11): content-addressed blobs are
// public-by-knowledge-of-CID, so opportunity (商談) payloads are encrypted
// client-side BEFORE `yataverse put` / D1 store, and only the ciphertext
// envelope is stored. The Worker never sees keys, passphrases, or
// plaintext; search/report over plaintext happens client-side only.
//
// Envelope v2 (owner-approved E2EE stage-2 parameters):
//   - Per-object random 256-bit DEK encrypts the payload (AES-256-GCM).
//   - The DEK is wrapped with a KEK derived from the user passphrase via
//     PBKDF2-HMAC-SHA256, 600,000 iterations, 128-bit random salt stored in
//     the envelope header (non-secret). WebCrypto only, no new dependency.
//   - AAD = "eigyo:opportunity:v2" (key-wrap uses a distinct AAD suffix).
//   - Envelope (JSON):
//       { v: 2, alg: "AES-256-GCM", iv: <b64 12B>, data: <b64 ciphertext>,
//         wrappedKey: { alg: "AES-256-GCM", iv: <b64 12B>, data: <b64 wrapped DEK> },
//         kdf: { name: "PBKDF2-HMAC-SHA256", iterations: 600000, salt: <b64 16B> } }
//   - Rotation = re-wrap DEK only (data untouched); DEK rotation = re-seal.
//   - v1 -> v2 migration: open the v1 envelope, re-seal as v2 (see
//     migrateToV2). v1 open support is kept until migration is done.
//
// Passphrases, DEKs, KEKs, and raw key bytes never live in this repo — they
// are runtime parameters injected by callers. Tests use synthetic
// passphrases and synthetic payloads only ("Synthetic Deal Alpha" etc.).

export const SEAL_ALG = "AES-256-GCM"; // envelope label (JWA name)
const WEBCRYPTO_ALG = "AES-GCM"; // WebCrypto algorithm name (NOT AES-256-GCM)

export const KDF_NAME = "PBKDF2-HMAC-SHA256";
export const KDF_ITERATIONS = 600_000;
const KDF_SALT_BYTES = 16; // 128-bit random salt, stored in the header.
const KDF_HASH = "SHA-256";
const DEK_BYTES = 32; // 256-bit per-object DEK.
const IV_BYTES = 12; // 96-bit GCM IV.

const AAD_V1 = new TextEncoder().encode("eigyo:opportunity:v1");
const AAD_V2 = new TextEncoder().encode("eigyo:opportunity:v2");
const AAD_WRAP = new TextEncoder().encode("eigyo:opportunity:v2:wrap");

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

function toPassphraseBytes(passphrase) {
  if (typeof passphrase === "string") return new TextEncoder().encode(passphrase);
  if (passphrase instanceof Uint8Array) return passphrase;
  throw new TypeError("[eigyo/seal] passphrase must be a string or Uint8Array");
}

// Derive a 256-bit KEK (AES-GCM CryptoKey) from a passphrase via
// PBKDF2-HMAC-SHA256. The KEK never leaves the client.
async function deriveKek(passphrase, salt, iterations, cryptoImpl) {
  const baseKey = await cryptoImpl.subtle.importKey(
    "raw",
    toPassphraseBytes(passphrase),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await cryptoImpl.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: KDF_HASH },
    baseKey,
    256,
  );
  return cryptoImpl.subtle.importKey(
    "raw",
    new Uint8Array(bits),
    { name: WEBCRYPTO_ALG },
    false,
    ["encrypt", "decrypt"],
  );
}

function randomBytes(n, cryptoImpl) {
  return cryptoImpl.getRandomValues(new Uint8Array(n));
}

async function importDek(dekBytes, cryptoImpl) {
  return cryptoImpl.subtle.importKey(
    "raw",
    dekBytes,
    { name: WEBCRYPTO_ALG },
    false,
    ["encrypt", "decrypt"],
  );
}

// ---- v1 (legacy, kept openable until v1 -> v2 migration is done) ----

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

// Legacy v1 sealer. Kept only so v1 fixtures / migration can be produced
// and tested; new sealing must go through sealPayload (v2).
export async function sealPayloadV1(value, key, cryptoImpl = globalThis.crypto) {
  const iv = cryptoImpl.getRandomValues(new Uint8Array(12));
  const ciphertext = await cryptoImpl.subtle.encrypt(
    { name: WEBCRYPTO_ALG, iv, additionalData: AAD_V1 },
    key,
    new TextEncoder().encode(JSON.stringify(value)),
  );
  return { v: 1, alg: "AES-256-GCM", iv: b64encode(iv), data: b64encode(new Uint8Array(ciphertext)) };
}

async function openV1(envelope, key, cryptoImpl) {
  const plaintext = await cryptoImpl.subtle.decrypt(
    { name: WEBCRYPTO_ALG, iv: b64decode(envelope.iv), additionalData: AAD_V1 },
    key,
    b64decode(envelope.data),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ---- v2 (current) ----

// Encrypt any JSON-serializable payload (e.g. an opportunity snapshot)
// with a passphrase. Returns a v2 envelope (ciphertext only — no plaintext,
// no passphrase, no KEK/DEK in recoverable form).
export async function sealPayload(value, passphrase, cryptoImpl = globalThis.crypto) {
  const salt = randomBytes(KDF_SALT_BYTES, cryptoImpl);
  const dekBytes = randomBytes(DEK_BYTES, cryptoImpl);
  const kek = await deriveKek(passphrase, salt, KDF_ITERATIONS, cryptoImpl);
  const dek = await importDek(dekBytes, cryptoImpl);

  const iv = randomBytes(IV_BYTES, cryptoImpl);
  const ciphertext = await cryptoImpl.subtle.encrypt(
    { name: WEBCRYPTO_ALG, iv, additionalData: AAD_V2 },
    dek,
    new TextEncoder().encode(JSON.stringify(value)),
  );

  const wrapIv = randomBytes(IV_BYTES, cryptoImpl);
  const wrappedDek = await cryptoImpl.subtle.encrypt(
    { name: WEBCRYPTO_ALG, iv: wrapIv, additionalData: AAD_WRAP },
    kek,
    dekBytes,
  );

  return {
    v: 2,
    alg: SEAL_ALG,
    iv: b64encode(iv),
    data: b64encode(new Uint8Array(ciphertext)),
    wrappedKey: {
      alg: SEAL_ALG,
      iv: b64encode(wrapIv),
      data: b64encode(new Uint8Array(wrappedDek)),
    },
    kdf: {
      name: KDF_NAME,
      iterations: KDF_ITERATIONS,
      salt: b64encode(salt),
    },
  };
}

function assertV2Shape(envelope) {
  if (envelope.alg !== SEAL_ALG) {
    throw new TypeError("[eigyo/seal] unsupported envelope algorithm");
  }
  if (typeof envelope.iv !== "string" || typeof envelope.data !== "string") {
    throw new TypeError("[eigyo/seal] malformed v2 envelope (iv/data)");
  }
  const wk = envelope.wrappedKey;
  if (!wk || wk.alg !== SEAL_ALG || typeof wk.iv !== "string" || typeof wk.data !== "string") {
    throw new TypeError("[eigyo/seal] malformed v2 envelope (wrappedKey)");
  }
  const kdf = envelope.kdf;
  if (!kdf || kdf.name !== KDF_NAME || !Number.isInteger(kdf.iterations) || kdf.iterations <= 0 ||
      typeof kdf.salt !== "string") {
    throw new TypeError("[eigyo/seal] malformed v2 envelope (kdf)");
  }
}

async function unwrapDek(envelope, passphrase, cryptoImpl) {
  const kdf = envelope.kdf;
  const kek = await deriveKek(passphrase, b64decode(kdf.salt), kdf.iterations, cryptoImpl);
  const dekBytes = await cryptoImpl.subtle.decrypt(
    { name: WEBCRYPTO_ALG, iv: b64decode(envelope.wrappedKey.iv), additionalData: AAD_WRAP },
    kek,
    b64decode(envelope.wrappedKey.data),
  );
  return importDek(new Uint8Array(dekBytes), cryptoImpl);
}

async function openV2(envelope, passphrase, cryptoImpl) {
  assertV2Shape(envelope);
  const dek = await unwrapDek(envelope, passphrase, cryptoImpl);
  const plaintext = await cryptoImpl.subtle.decrypt(
    { name: WEBCRYPTO_ALG, iv: b64decode(envelope.iv), additionalData: AAD_V2 },
    dek,
    b64decode(envelope.data),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// Decrypt an envelope. v1 expects a CryptoKey (legacy); v2 expects the
// passphrase (string/Uint8Array). Wrong key/passphrase or tampered
// ciphertext throws (AES-GCM authentication failure); no plaintext is ever
// returned.
export async function openPayload(envelope, credential, cryptoImpl = globalThis.crypto) {
  if (!envelope || (envelope.v !== 1 && envelope.v !== 2)) {
    throw new TypeError("[eigyo/seal] unsupported envelope version");
  }
  if (envelope.v === 1) return openV1(envelope, credential, cryptoImpl);
  return openV2(envelope, credential, cryptoImpl);
}

// KEK rotation: re-wrap the existing DEK under a new passphrase (new salt +
// new wrap IV). The payload ciphertext (iv/data) is left untouched.
export async function rewrapPayload(envelope, oldPassphrase, newPassphrase, cryptoImpl = globalThis.crypto) {
  if (!envelope || envelope.v !== 2) {
    throw new TypeError("[eigyo/seal] rewrapPayload requires a v2 envelope");
  }
  assertV2Shape(envelope);
  const oldKek = await deriveKek(
    oldPassphrase,
    b64decode(envelope.kdf.salt),
    envelope.kdf.iterations,
    cryptoImpl,
  );
  const dekBytes = new Uint8Array(
    await cryptoImpl.subtle.decrypt(
      { name: WEBCRYPTO_ALG, iv: b64decode(envelope.wrappedKey.iv), additionalData: AAD_WRAP },
      oldKek,
      b64decode(envelope.wrappedKey.data),
    ),
  );
  const salt = randomBytes(KDF_SALT_BYTES, cryptoImpl);
  const newKek = await deriveKek(newPassphrase, salt, KDF_ITERATIONS, cryptoImpl);
  const wrapIv = randomBytes(IV_BYTES, cryptoImpl);
  const wrappedDek = await cryptoImpl.subtle.encrypt(
    { name: WEBCRYPTO_ALG, iv: wrapIv, additionalData: AAD_WRAP },
    newKek,
    dekBytes,
  );
  return {
    ...envelope,
    wrappedKey: {
      alg: SEAL_ALG,
      iv: b64encode(wrapIv),
      data: b64encode(new Uint8Array(wrappedDek)),
    },
    kdf: { name: KDF_NAME, iterations: KDF_ITERATIONS, salt: b64encode(salt) },
  };
}

// DEK rotation = re-seal: open the envelope, then seal the same plaintext
// under a new passphrase (fresh DEK, fresh salt, fresh ciphertext).
export async function resealPayload(envelope, credential, newPassphrase, cryptoImpl = globalThis.crypto) {
  const plaintext = await openPayload(envelope, credential, cryptoImpl);
  return sealPayload(plaintext, newPassphrase, cryptoImpl);
}

// v1 -> v2 migration: open the v1 envelope with the legacy CryptoKey,
// re-seal as v2 under the user's passphrase. The v1 envelope itself is
// untouched; callers store the returned v2 envelope.
export async function migrateToV2(v1Envelope, legacyKey, newPassphrase, cryptoImpl = globalThis.crypto) {
  if (!v1Envelope || v1Envelope.v !== 1) {
    throw new TypeError("[eigyo/seal] migrateToV2 requires a v1 envelope");
  }
  const plaintext = await openV1(v1Envelope, legacyKey, cryptoImpl);
  return sealPayload(plaintext, newPassphrase, cryptoImpl);
}
