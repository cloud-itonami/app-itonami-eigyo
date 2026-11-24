// app-itonami-eigyo — Awai identity auth (did:key + Ed25519 via WebCrypto).
//
// Ed25519 is WebCrypto ONLY (crypto.subtle importKey/sign/verify with
// { name: "Ed25519" }). This runtime (Node `node --test` and Cloudflare
// Workers) supports WebCrypto Ed25519: importKey("pkcs8"/"raw") and
// verify work, at ~0.05 ms/verify (vs ~143 ms for a pure-JS BigInt
// implementation, which exceeds the Workers Free 10 ms CPU cap). There
// is NO pure-JS curve arithmetic in this file: no scalarMult, no modInv,
// no secret-scalar code. Signing and verification are delegated to the
// platform WebCrypto implementation, whose scalar operations are not
// observable from JS and are not subject to JS-level timing leakage.
// Private keys never reach the Worker; the Worker only holds public
// keys (from dids), single-use nonces, and session ids in memory.
// Kougi review points addressed here:
//   K1 (non-constant-time scalarMult / Fermat modInv) — GONE: the pure-JS
//      implementation is deleted. No secret-scalar arithmetic remains
//      anywhere in this codebase (client or server); signing is
//      WebCrypto-only.
//   K2 (small-order / non-canonical public-key encodings) — WebCrypto
//      Ed25519 verify is cofactorless in this runtime and ACCEPTS a
//      forged signature under the identity (small-order) public key
//      (measured: verify(identity, basepoint||S=1) === true), and it
//      accepts non-canonical encodings at importKey time. WebCrypto
//      alone therefore does NOT resolve K2. ed25519Verify below adds
//      explicit public-data checks before delegating to WebCrypto:
//      (a) public key and R must be canonical (y < p), (b) neither may
//      be a known small-order (8-torsion) encoding (libsodium
//      `ge25519_has_small_order` table, sign-bit twin included), and
//      (c) S must be canonical (S < L). These checks operate only on
//      public encodings; they use BigInt comparisons on public data,
//      not secret scalars. With them, the identity forgery above is
//      rejected (see test/worker.test.js K2 tests).
//
// TODO (item 8, out of scope this PR — pre-deploy, separate PR): nonces
// and sessions are currently held in an isolate-local Map. Moving them
// to D1/DO with an expiry sweep is pre-deploy work; until then an
// isolate restart simply forces re-authentication (new challenge).
//
// Protocol:
//   did:key:z<base58btc multicodec ed25519-pubkey>  (prefix bytes ed 01)
//   POST /auth/challenge {did}         -> {did, nonce, purpose, timestamp, expiresAt}
//   POST /auth/verify    {did, nonce, signature}
//     signature = base64(Ed25519-sign(canonical message)) where the
//     canonical message is UTF-8 of  nonce||purpose||timestamp .
//   verify issues a short-lived, DID-bound session id (5 minutes),
//   presented via `x-did` + `x-session` headers (no Bearer, per owner
//   decision — same as kokyaku).
// Private keys, passphrases, and KEKs are client-side only and NEVER
// reach the Worker.

const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

function concatBytes(...parts) {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function b64urlToBytes(text) {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(Math.ceil(b64.length / 4) * 4, "=");
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---- public-encoding validity (K2): canonical y, small-order, canonical S ----
// p = 2^255 - 19, L = 2^252 + 27742317777372353535851937790883648493
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function intFromLeBytes(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function yOfEncoding(bytes32) {
  const yBytes = Uint8Array.from(bytes32);
  yBytes[31] &= 0x7f; // strip x sign bit
  return intFromLeBytes(yBytes);
}

function isCanonicalEncoding(bytes32) {
  if (!(bytes32 instanceof Uint8Array) || bytes32.length !== 32) return false;
  return yOfEncoding(bytes32) < P;
}

// libsodium `ge25519_has_small_order` (ref10) canonical 8-torsion encodings;
// the sign-bit twin (last byte | 0x80) is the same point and equally banned.
const SMALL_ORDER_HEX = [
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000000",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
];
const SMALL_ORDER_PREFIX31 = SMALL_ORDER_HEX.map((h) => h.slice(0, 62));
const SMALL_ORDER_LAST7 = SMALL_ORDER_HEX.map((h) => parseInt(h.slice(62, 64), 16) & 0x7f);

export function isSmallOrderEncoding(bytes32) {
  if (!(bytes32 instanceof Uint8Array) || bytes32.length !== 32) return false;
  const hex = [...bytes32].map((b) => b.toString(16).padStart(2, "0")).join("");
  const prefix = hex.slice(0, 62);
  const last = bytes32[31] & 0x7f;
  for (let i = 0; i < SMALL_ORDER_PREFIX31.length; i++) {
    if (prefix === SMALL_ORDER_PREFIX31[i] && last === SMALL_ORDER_LAST7[i]) return true;
  }
  return false;
}

export function isCanonicalPublicKey(bytes32) {
  return isCanonicalEncoding(bytes32) && !isSmallOrderEncoding(bytes32);
}

function isCanonicalS(signature) {
  const s = intFromLeBytes(signature.slice(32, 64));
  return s >= 0n && s < L;
}

// ---- Ed25519 via WebCrypto ----
async function importPrivateFromSeed(seed32, cryptoImpl) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new RangeError("[eigyo/auth] ed25519 seed must be 32 bytes");
  }
  const der = concatBytes(PKCS8_ED25519_PREFIX, seed32);
  return cryptoImpl.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
}

// 32-byte seed -> 32-byte public key, via WebCrypto (private JWK `x`).
export async function ed25519PublicKeyFromSeed(seed32, cryptoImpl = globalThis.crypto) {
  const priv = await importPrivateFromSeed(seed32, cryptoImpl);
  const jwk = await cryptoImpl.subtle.exportKey("jwk", priv);
  if (!jwk || typeof jwk.x !== "string") {
    throw new Error("[eigyo/auth] WebCrypto did not return Ed25519 public JWK");
  }
  const publicKey = b64urlToBytes(jwk.x);
  if (publicKey.length !== 32) throw new Error("[eigyo/auth] bad Ed25519 public key length");
  return publicKey;
}

// Sign message with a 32-byte seed (private key). Returns 64-byte signature.
export async function ed25519Sign(seed32, message, cryptoImpl = globalThis.crypto) {
  const msg = message instanceof Uint8Array ? message : new TextEncoder().encode(String(message));
  const priv = await importPrivateFromSeed(seed32, cryptoImpl);
  return new Uint8Array(await cryptoImpl.subtle.sign({ name: "Ed25519" }, priv, msg));
}

// Verify a 64-byte signature against a 32-byte public key. Any malformed
// input or failed equation returns false (never throws for bad sigs).
// Public-encoding checks (K2) run before WebCrypto verify, because the
// platform verify is cofactorless and accepts small-order forgeries.
export async function ed25519Verify(publicKey, message, signature, cryptoImpl = globalThis.crypto) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false;
    if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
    if (!isCanonicalPublicKey(publicKey)) return false;
    if (!isCanonicalEncoding(signature.slice(0, 32))) return false;
    if (isSmallOrderEncoding(signature.slice(0, 32))) return false;
    if (!isCanonicalS(signature)) return false;
    const msg = message instanceof Uint8Array ? message : new TextEncoder().encode(String(message));
    const key = await cryptoImpl.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return await cryptoImpl.subtle.verify({ name: "Ed25519" }, key, signature, msg);
  } catch {
    return false;
  }
}

// Generate a fresh seed + public key (client-side only; the seed is the
// private key and is never sent to the Worker).
export async function ed25519GenerateKeypair(cryptoImpl = globalThis.crypto) {
  const keypair = await cryptoImpl.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await cryptoImpl.subtle.exportKey("raw", keypair.publicKey));
  const pkcs8 = new Uint8Array(await cryptoImpl.subtle.exportKey("pkcs8", keypair.privateKey));
  if (publicKey.length !== 32 || pkcs8.length !== 48) {
    throw new Error("[eigyo/auth] unexpected Ed25519 key export length");
  }
  const seed = pkcs8.slice(-32);
  return { seed: new Uint8Array(seed), publicKey };
}

// ---- base58btc (Bitcoin alphabet) ----
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_INDEX = new Map([...B58_ALPHABET].map((ch, i) => [ch, i]));

export function b58encode(bytes) {
  const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let leadingZeros = 0;
  while (leadingZeros < input.length && input[leadingZeros] === 0) leadingZeros++;
  if (leadingZeros === input.length) return "1".repeat(input.length);
  let value = 0n;
  for (const b of input) value = (value << 8n) | BigInt(b);
  let encoded = "";
  while (value > 0n) {
    encoded = B58_ALPHABET[Number(value % 58n)] + encoded;
    value /= 58n;
  }
  return "1".repeat(leadingZeros) + encoded;
}

export function b58decode(text) {
  let leadingOnes = 0;
  while (leadingOnes < text.length && text[leadingOnes] === "1") leadingOnes++;
  if (leadingOnes === text.length && text.length > 0) return new Uint8Array(text.length);
  let value = 0n;
  for (const ch of text) {
    const digit = B58_INDEX.get(ch);
    if (digit === undefined) throw new Error(`[eigyo/auth] invalid base58 character: ${ch}`);
    value = value * 58n + BigInt(digit);
  }
  const body = [];
  while (value > 0n) {
    body.unshift(Number(value & 0xffn));
    value >>= 8n;
  }
  const out = new Uint8Array(leadingOnes + body.length);
  out.set(body, leadingOnes);
  return out;
}

// did:key:z<base58btc(0xed 0x01 || pubkey32)> — multicodec ed25519-pubkey.
export function pubkeyToDid(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new RangeError("[eigyo/auth] public key must be 32 bytes");
  }
  return `did:key:z${b58encode(concatBytes(new Uint8Array([0xed, 0x01]), publicKey))}`;
}

export function didToPubkey(did) {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) {
    throw new Error("[eigyo/auth] invalid did:key");
  }
  const decoded = b58decode(did.slice("did:key:z".length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("[eigyo/auth] invalid did:key (expected ed25519-pubkey multicodec)");
  }
  return decoded.slice(2);
}

// ---- challenge / verify / session service ----
export const AUTH_PURPOSE = "eigyo:auth:login";
export const NONCE_TTL_MS = 5 * 60 * 1000; // single-use, short-lived
export const SESSION_TTL_MS = 5 * 60 * 1000; // short-lived, DID-bound (5 min, same as nonce)

export function canonicalAuthMessage({ nonce, purpose, timestamp }) {
  return `${nonce}||${purpose}||${timestamp}`;
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function createAuthService({ now = () => Date.now(), cryptoImpl = globalThis.crypto } = {}) {
  // TODO(item 8): isolate-local Maps — move nonces/sessions to D1/DO with
  // expiry sweep in a separate pre-deploy PR (see header comment).
  const nonces = new Map(); // nonce -> challenge record
  const sessions = new Map(); // session id -> { did, expiresAtMs }

  function randomHex(byteCount) {
    return bytesToHex(cryptoImpl.getRandomValues(new Uint8Array(byteCount)));
  }

  function issueChallenge(did) {
    let publicKey;
    try {
      publicKey = didToPubkey(did);
    } catch {
      return { ok: false, error: "invalid-did" };
    }
    if (publicKey.length !== 32) return { ok: false, error: "invalid-did" };
    const nonce = randomHex(16);
    const purpose = AUTH_PURPOSE;
    const issuedAtMs = now();
    const timestamp = new Date(issuedAtMs).toISOString();
    const record = {
      did,
      nonce,
      purpose,
      timestamp,
      expiresAtMs: issuedAtMs + NONCE_TTL_MS,
      used: false,
    };
    nonces.set(nonce, record);
    return {
      ok: true,
      did,
      nonce,
      purpose,
      timestamp,
      expiresAt: new Date(record.expiresAtMs).toISOString(),
    };
  }

  async function verifyResponse({ did, nonce, signature } = {}) {
    const record = typeof nonce === "string" ? nonces.get(nonce) : undefined;
    // Single-use: consume the nonce on the first verify attempt (success or
    // failure) so a captured signature can never be replayed.
    const wasUnused = !!record && !record.used;
    if (record) record.used = true;
    if (!wasUnused) return { ok: false, error: "auth-failed" };
    if (record.did !== did) return { ok: false, error: "auth-failed" };
    if (now() > record.expiresAtMs) return { ok: false, error: "auth-failed" };
    if (typeof signature !== "string") return { ok: false, error: "auth-failed" };
    let publicKey;
    try {
      publicKey = didToPubkey(did);
    } catch {
      return { ok: false, error: "auth-failed" };
    }
    let sigBytes;
    try {
      sigBytes = b64ToBytes(signature);
    } catch {
      return { ok: false, error: "auth-failed" };
    }
    const message = canonicalAuthMessage(record);
    const valid = await ed25519Verify(publicKey, new TextEncoder().encode(message), sigBytes, cryptoImpl);
    if (!valid) return { ok: false, error: "auth-failed" };
    const session = randomHex(32);
    const expiresAtMs = now() + SESSION_TTL_MS;
    sessions.set(session, { did, expiresAtMs });
    return { ok: true, session, did, expiresAt: new Date(expiresAtMs).toISOString() };
  }

  // getSession(sessionId, did?) — when did is given, the session must be
  // bound to that DID (x-did + x-session), otherwise null.
  function getSession(session, did) {
    if (typeof session !== "string" || !session) return null;
    const record = sessions.get(session);
    if (!record) return null;
    if (now() > record.expiresAtMs) {
      sessions.delete(session);
      return null;
    }
    if (did !== undefined && did !== null && record.did !== did) return null;
    return record.did;
  }

  return { issueChallenge, verifyResponse, getSession, _stores: { nonces, sessions } };
}
