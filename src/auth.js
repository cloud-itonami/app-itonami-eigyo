// app-itonami-eigyo — Awai identity auth (did:key + Ed25519).
//
// WebCrypto has no Ed25519 in the runtimes this Worker runs in (Node
// `node --test` and Cloudflare Workers alike), so verification is a small
// pure-JS BigInt implementation with zero new dependencies. SHA-512 comes
// from WebCrypto (`crypto.subtle.digest("SHA-512", …)`), which IS present
// in both runtimes; only the curve arithmetic is hand-rolled. Signing is
// included because the client side needs it (tests sign challenge
// responses with generated keypairs). Verified against RFC 8032 test
// vectors in test/worker.test.js. Dependency impact: none — plain JS,
// BigInt, and WebCrypto SHA-512.
//
// Protocol:
//   did:key:z<base58btc multicodec ed25519-pubkey>  (prefix bytes ed 01)
//   POST /auth/challenge {did}         -> {did, nonce, purpose, timestamp, expiresAt}
//   POST /auth/verify    {did, nonce, signature}
//     signature = base64(Ed25519-sign(canonical message)) where the
//     canonical message is UTF-8 of  nonce||purpose||timestamp .
//   verify issues a short-lived, DID-bound Bearer session token.
// Private keys, passphrases, and KEKs are client-side only and NEVER reach
// the Worker: the Worker holds public keys (from dids), single-use
// nonces, and session tokens in memory, and nothing else — there is no
// Worker secret for key material.

function sha512(bytes, cryptoImpl = globalThis.crypto) {
  return cryptoImpl.subtle.digest("SHA-512", bytes).then((buf) => new Uint8Array(buf));
}

// ---- field arithmetic (mod p = 2^255 - 19) ----
const Q = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;

function mod(a, n) {
  const r = a % n;
  return r >= 0n ? r : r + n;
}

function modPow(base, exp, m) {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

function modInv(a, m) {
  return modPow(a, m - 2n, m);
}

const D = mod(-121665n * modInv(121666n, Q), Q);
const I = modPow(2n, (Q - 1n) / 4n, Q); // sqrt(-1) mod q

function xrecover(y, signBit) {
  const yy = mod(y * y, Q);
  const xx = mod((yy - 1n) * modInv(mod(D * yy + 1n, Q), Q), Q);
  let x = modPow(xx, (Q + 3n) / 8n, Q);
  if (mod(x * x - xx, Q) !== 0n) x = mod(x * I, Q);
  if (mod(x * x - xx, Q) !== 0n) throw new Error("invalid point");
  const isOdd = (x & 1n) === 1n;
  // Ed25519 "negative" sign = odd x. Negate unless oddness matches sign.
  if (isOdd !== (signBit === 1)) x = mod(-x, Q);
  return x;
}

const BY = mod(4n * modInv(5n, Q), Q);
const BASE = { x: xrecover(BY, 0), y: BY };

function pointAdd(p1, p2) {
  const x1x2 = mod(p1.x * p2.x, Q);
  const y1y2 = mod(p1.y * p2.y, Q);
  const t = mod(D * mod(x1x2 * y1y2, Q), Q);
  const x3 = mod(mod(p1.x * p2.y + p2.x * p1.y, Q) * modInv(mod(1n + t, Q), Q), Q);
  const y3 = mod(mod(y1y2 + x1x2, Q) * modInv(mod(1n - t, Q), Q), Q);
  return { x: x3, y: y3 };
}

function scalarMult(point, scalar) {
  let result = { x: 0n, y: 1n }; // identity
  let addend = point;
  let s = scalar;
  while (s > 0n) {
    if (s & 1n) result = pointAdd(result, addend);
    addend = pointAdd(addend, addend);
    s >>= 1n;
  }
  return result;
}

// ---- point / scalar encoding ----
function intFromLeBytes(bytes) {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function intToLeBytes(value, length) {
  const bytes = new Uint8Array(length);
  let v = value;
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

function encodePoint(point) {
  const bytes = intToLeBytes(point.y, 32);
  if ((point.x & 1n) === 1n) bytes[31] |= 0x80;
  return bytes;
}

function decodePoint(bytes) {
  if (bytes.length !== 32) throw new Error("invalid point encoding");
  const yBytes = Uint8Array.from(bytes);
  const signBit = (yBytes[31] >> 7) & 1;
  yBytes[31] &= 0x7f;
  const y = intFromLeBytes(yBytes);
  const x = xrecover(y, signBit);
  return { x, y };
}

function clampScalar(h32) {
  const bytes = Uint8Array.from(h32);
  bytes[0] &= 248;
  bytes[31] &= 127;
  bytes[31] |= 64;
  return intFromLeBytes(bytes);
}

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

// ---- Ed25519 (RFC 8032) ----
async function expandSeed(seed32, cryptoImpl) {
  const h = await sha512(seed32, cryptoImpl);
  return {
    scalar: clampScalar(h.slice(0, 32)),
    prefix: h.slice(32, 64),
  };
}

// 32-byte seed -> { publicKey: Uint8Array(32) }
export async function ed25519PublicKeyFromSeed(seed32, cryptoImpl = globalThis.crypto) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new RangeError("[eigyo/auth] ed25519 seed must be 32 bytes");
  }
  const { scalar } = await expandSeed(seed32, cryptoImpl);
  return encodePoint(scalarMult(BASE, scalar));
}

// Sign message with a 32-byte seed (private key). Returns the 64-byte
// signature (RFC 8032 deterministic nonce scheme).
export async function ed25519Sign(seed32, message, cryptoImpl = globalThis.crypto) {
  if (!(seed32 instanceof Uint8Array) || seed32.length !== 32) {
    throw new RangeError("[eigyo/auth] ed25519 seed must be 32 bytes");
  }
  const msg = message instanceof Uint8Array ? message : new TextEncoder().encode(String(message));
  const { scalar, prefix } = await expandSeed(seed32, cryptoImpl);
  const publicKey = encodePoint(scalarMult(BASE, scalar));
  const r = mod(intFromLeBytes(await sha512(concatBytes(prefix, msg), cryptoImpl)), L);
  const rEncoded = encodePoint(scalarMult(BASE, r));
  const k = mod(intFromLeBytes(await sha512(concatBytes(rEncoded, publicKey, msg), cryptoImpl)), L);
  const s = mod(r + mod(k * scalar, L), L);
  return concatBytes(rEncoded, intToLeBytes(s, 32));
}

// Verify a 64-byte signature against a 32-byte public key. Any malformed
// input or failed equation returns false (never throws for bad sigs).
export async function ed25519Verify(publicKey, message, signature, cryptoImpl = globalThis.crypto) {
  try {
    if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) return false;
    if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
    const msg = message instanceof Uint8Array ? message : new TextEncoder().encode(String(message));
    const rEncoded = signature.slice(0, 32);
    const sBytes = signature.slice(32, 64);
    const s = intFromLeBytes(sBytes);
    if (s >= L || s < 0n) return false;
    const aPoint = decodePoint(publicKey);
    const rPoint = decodePoint(rEncoded);
    const k = intFromLeBytes(await sha512(concatBytes(rEncoded, publicKey, msg), cryptoImpl));
    const left = encodePoint(scalarMult(BASE, s));
    const right = encodePoint(pointAdd(rPoint, scalarMult(aPoint, mod(k, L))));
    return bytesEqual(left, right);
  } catch {
    return false;
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Generate a fresh seed + public key (client-side only; the seed is the
// private key and is never sent to the Worker).
export async function ed25519GenerateKeypair(cryptoImpl = globalThis.crypto) {
  const seed = cryptoImpl.getRandomValues(new Uint8Array(32));
  const publicKey = await ed25519PublicKeyFromSeed(seed, cryptoImpl);
  return { seed, publicKey };
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
export const SESSION_TTL_MS = 30 * 60 * 1000; // short-lived, DID-bound

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
  const nonces = new Map(); // nonce -> challenge record
  const sessions = new Map(); // token -> { did, expiresAtMs }

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
    const token = randomHex(32);
    const expiresAtMs = now() + SESSION_TTL_MS;
    sessions.set(token, { did, expiresAtMs });
    return { ok: true, token, did, expiresAt: new Date(expiresAtMs).toISOString() };
  }

  function getSession(token) {
    if (typeof token !== "string" || !token) return null;
    const session = sessions.get(token);
    if (!session) return null;
    if (now() > session.expiresAtMs) {
      sessions.delete(token);
      return null;
    }
    return session.did;
  }

  return { issueChallenge, verifyResponse, getSession, _stores: { nonces, sessions } };
}
