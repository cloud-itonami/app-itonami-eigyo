// app-itonami-eigyo Worker — plain JS, zero dependencies.
// R2 NON-DEPENDENCE (owner policy 2026-11-23): no R2 binding, no R2 API.
// Content read:  GET https://yataverse.com/ipfs/<cid> (verified against CID)
// Content write: yataverse put (out of scope for this Worker — no write route)
//
// E2EE STAGE-2 (docs/sfa.md §11):
// - Persistence = env.EIGYO_DB (D1 binding in wrangler.jsonc; zero-UUID
//   placeholder, not created) holding sealed_records ONLY: ciphertext +
//   metadata, no plaintext columns. The plaintext in-memory store is GONE as
//   a persistence path: when no EIGYO_DB binding is present (local
//   `node --test`, wrangler dev without D1), a clearly-marked DEMO fallback
//   holds sealed envelopes (ciphertext only, never plaintext) so the
//   handlers can be exercised without D1. Search/report over plaintext
//   happens client-side only (src/sfa.js operates on decrypted data);
//   there is deliberately no server-side plaintext search/report route.
// - Auth = Awai identity did:key. POST /auth/challenge issues a single-use
//   short-lived nonce; POST /auth/verify checks the Ed25519 signature
//   (WebCrypto, src/auth.js) against the DID public key and issues a
//   short-lived DID-bound session. Sessions are presented via `x-did` +
//   `x-session` headers (owner decision: no Authorization: Bearer, same as
//   kokyaku). Owner scope = the verified DID. The old role/userId
//   query-param trust is REMOVED — protected routes accept only a verified
//   session. Private keys, passphrases and KEKs never reach this Worker.
//   Lifetimes: challenge nonce 5 minutes AND session 5 minutes.
//   TODO(item 8, out of scope this PR): nonces/sessions are isolate-local
//   Maps (src/auth.js); moving them to D1/DO with an expiry sweep is
//   pre-deploy work for a separate PR.
// - Missing objects answer 404, never 500 (cf. no-r2-yataverse-only.md);
//   bad CID -> 400 before any fetch runs; malformed %-encoding -> 400,
//   never a thrown URIError. D1 constraint violation -> 409, any other
//   store failure -> 503.
// - POST /records accepts envelope v2 ONLY (v1 is client-side
//   open-then-reseal migration only, never a new save). Envelopes are
//   rebuilt from allowlisted keys only and validated strictly (base64 +
//   fixed lengths, KDF 600,000 / salt 16B) — unknown keys -> 400, never
//   stored. Record ids must be server-issued (`record_<32 hex>`) or UUID.
//
// HTTP surface (see docs/sfa.md §7/§11):
//   GET  /health
//   GET  /ipfs/<cid>                       yataverse proxy (public)
//   POST /auth/challenge  {did}            -> 201 {nonce, purpose, timestamp} | 400
//   POST /auth/verify     {did, nonce, signature} -> 200 {session, did, expiresAt} | 401
//   POST /records         (x-did+x-session) {id?, cid?, envelope, seq?} -> 201 metadata | 400 | 401 | 409 | 503
//   GET  /records         (x-did+x-session) -> 200 {items:[metadata...]} (own only) | 401 | 503
//   GET  /records/:id     (x-did+x-session) -> 200 record | 404 | 401 | 400 | 503

import { createAuthService } from "./auth.js";

const YATAVERSE = "https://yataverse.com";
const authService = createAuthService();

// DEMO ONLY fallback: holds SEALED envelopes (ciphertext + metadata) when
// env.EIGYO_DB is absent. Never stores plaintext; real persistence is D1.
const demoRecords = new Map();

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// Reject blank / traversal / control-char CIDs before any fetch runs.
// Char-class guards use \u escapes, never literal control bytes.
function validCid(cid) {
  return cid && !cid.includes("/") && !cid.includes("\\") && !cid.includes("..") &&
    !/[\s\u0000-\u001f\u007f]/.test(cid);
}

// decodeURIComponent throws URIError on malformed %-encoding (e.g. %E0%A4).
// The contract is 400/404, never a throw — decode safely, null on bad input.
function safeDecode(text) {
  try {
    return decodeURIComponent(text);
  } catch {
    return null;
  }
}

async function handleIpfs(cid, fetchImpl) {
  if (!validCid(cid)) return json({ error: "bad-cid", cid }, 400);
  let upstream;
  try {
    upstream = await fetchImpl(`${YATAVERSE}/ipfs/${cid}`, {
      headers: { accept: "*/*" },
    });
  } catch {
    return json({ error: "image-unavailable", cid, source: "yataverse" }, 404);
  }
  if (!upstream.ok) return json({ error: "image-unavailable", cid, source: "yataverse" }, 404);
  const body = await upstream.arrayBuffer();
  const headers = new Headers();
  const ct = upstream.headers?.get?.("content-type");
  if (ct) headers.set("content-type", ct);
  headers.set("cache-control", "public, max-age=300");
  return new Response(body, { status: 200, headers });
}

// Session auth: x-did + x-session (no Bearer, per owner decision).
// The session must be bound to the presented DID.
function requireDid(request) {
  const did = request.headers?.get("x-did") || "";
  const session = request.headers?.get("x-session") || "";
  if (!did || !session) return null;
  const sessionDid = authService.getSession(session, did);
  return sessionDid === did ? did : null;
}

// ---- strict sealed-envelope validation (review #1, #2, #3) ----
// Per e2ee-params.md §2: {v, alg, iv, data, wrappedKey{alg,iv,data},
// kdf{name,iterations,salt}}. Only allowlisted keys are accepted; unknown
// keys anywhere -> 400. The stored envelope is REBUILT from the validated
// fields only, so nothing client-supplied beyond the allowlist is stored.
const ENVELOPE_KEYS = new Set(["v", "alg", "iv", "data", "wrappedKey", "kdf"]);
const WRAPPED_KEY_KEYS = new Set(["alg", "iv", "data"]);
const KDF_KEYS = new Set(["name", "iterations", "salt"]);
const BODY_KEYS = new Set(["id", "cid", "envelope", "seq"]);
const KDF_ITERATIONS = 600_000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SERVER_ID_RE = /^record_[0-9a-f]{32}$/;

function isValidRecordId(id) {
  return typeof id === "string" && (UUID_RE.test(id) || SERVER_ID_RE.test(id));
}

function hasOnlyKeys(obj, allowed) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return false;
  return Object.keys(obj).every((k) => allowed.has(k)) && Object.keys(obj).length === allowed.size;
}

// Strict base64: canonical alphabet/padding, re-encode must round-trip.
function b64ByteLength(value) {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return null;
  try {
    const bin = atob(value);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    let rebin = "";
    for (const b of bytes) rebin += String.fromCharCode(b);
    if (btoa(rebin) !== value) return null;
    return bytes.length;
  } catch {
    return null;
  }
}

// Returns a rebuilt envelope containing ONLY allowlisted fields, or null.
function rebuildEnvelope(envelope) {
  if (!hasOnlyKeys(envelope, ENVELOPE_KEYS)) return null;
  // v2 ONLY for new saves (#2): v1 is client-side migration only.
  if (envelope.v !== 2) return null;
  if (envelope.alg !== "AES-256-GCM") return null;
  // iv 12B, data >= 16B (ciphertext + GCM tag).
  if (b64ByteLength(envelope.iv) !== 12) return null;
  const dataLen = b64ByteLength(envelope.data);
  if (dataLen === null || dataLen < 16) return null;
  const wk = envelope.wrappedKey;
  if (!hasOnlyKeys(wk, WRAPPED_KEY_KEYS)) return null;
  if (wk.alg !== "AES-256-GCM") return null;
  if (b64ByteLength(wk.iv) !== 12) return null;
  // Wrapped DEK: 32B DEK + 16B GCM tag = 48B.
  if (b64ByteLength(wk.data) !== 48) return null;
  const kdf = envelope.kdf;
  if (!hasOnlyKeys(kdf, KDF_KEYS)) return null;
  if (kdf.name !== "PBKDF2-HMAC-SHA256") return null;
  // KDF fixation (#3): exactly 600,000 iterations and a 16B salt.
  if (kdf.iterations !== KDF_ITERATIONS) return null;
  if (b64ByteLength(kdf.salt) !== 16) return null;
  return {
    v: 2,
    alg: "AES-256-GCM",
    iv: envelope.iv,
    data: envelope.data,
    wrappedKey: { alg: "AES-256-GCM", iv: wk.iv, data: wk.data },
    kdf: { name: "PBKDF2-HMAC-SHA256", iterations: KDF_ITERATIONS, salt: kdf.salt },
  };
}

function newRecordId() {
  return `record_${globalThis.crypto.getRandomValues(new Uint8Array(16)).reduce((s, b) => s + b.toString(16).padStart(2, "0"), "")}`;
}

function metadataOf(row) {
  return {
    id: row.id,
    owner_id: row.owner_id,
    cid: row.cid ?? null,
    seq: row.seq ?? 0,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function isConstraintViolation(err) {
  return /constraint/i.test(String(err?.message ?? err));
}

async function storeRecord(env, row) {
  const db = env?.EIGYO_DB;
  if (!db) {
    if (demoRecords.has(row.id)) return { ok: false, error: "exists" };
    demoRecords.set(row.id, row);
    return { ok: true };
  }
  try {
    await db.prepare(
      "INSERT INTO sealed_records (id, owner_id, cid, envelope, seq, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).bind(row.id, row.owner_id, row.cid ?? null, row.envelope, row.seq ?? 0, row.created_at, row.updated_at).run();
    return { ok: true };
  } catch (err) {
    // Duplicate = constraint violation ONLY (#6); every other D1 failure
    // is a store outage (503), never a false 409.
    if (isConstraintViolation(err)) return { ok: false, error: "exists" };
    return { ok: false, error: "unavailable" };
  }
}

async function fetchRecordById(env, id) {
  const db = env?.EIGYO_DB;
  if (!db) return demoRecords.get(id) ?? null;
  const row = await db.prepare(
    "SELECT id, owner_id, cid, envelope, seq, created_at, updated_at FROM sealed_records WHERE id = ?",
  ).bind(id).first();
  return row ?? null;
}

async function listRecordsByOwner(env, ownerId) {
  const db = env?.EIGYO_DB;
  if (!db) {
    return [...demoRecords.values()]
      .filter((row) => row.owner_id === ownerId)
      .sort((a, b) => (a.seq - b.seq) || (a.created_at < b.created_at ? -1 : 1));
  }
  const result = await db.prepare(
    "SELECT id, owner_id, cid, envelope, seq, created_at, updated_at FROM sealed_records WHERE owner_id = ? ORDER BY seq, created_at",
  ).bind(ownerId).all();
  return result.results ?? [];
}

export async function fetchHandler(request, env, fetchImpl = fetch) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "GET" && path === "/health") {
    return json({ ok: true, service: "app-itonami-eigyo", storage: "yataverse", r2: false });
  }

  if (request.method === "GET" && path.startsWith("/ipfs/")) {
    const cid = safeDecode(path.slice("/ipfs/".length));
    if (cid === null) return json({ error: "bad-cid" }, 400);
    return handleIpfs(cid, fetchImpl);
  }

  if (request.method === "POST" && path === "/auth/challenge") {
    const body = await request.json().catch(() => null);
    const result = authService.issueChallenge(typeof body?.did === "string" ? body.did : "");
    if (!result.ok) return json({ error: "invalid-did" }, 400);
    return json({
      did: result.did,
      nonce: result.nonce,
      purpose: result.purpose,
      timestamp: result.timestamp,
      expiresAt: result.expiresAt,
    }, 201);
  }

  if (request.method === "POST" && path === "/auth/verify") {
    const body = await request.json().catch(() => null);
    const result = await authService.verifyResponse({
      did: typeof body?.did === "string" ? body.did : "",
      nonce: typeof body?.nonce === "string" ? body.nonce : "",
      signature: typeof body?.signature === "string" ? body.signature : "",
    });
    if (!result.ok) return json({ error: "auth-failed" }, 401);
    return json({ session: result.session, did: result.did, expiresAt: result.expiresAt });
  }

  if (request.method === "POST" && path === "/records") {
    const did = requireDid(request);
    if (!did) return json({ error: "unauthorized" }, 401);
    const body = await request.json().catch(() => null);
    if (!body || typeof body !== "object" || Array.isArray(body) ||
        !Object.keys(body).every((k) => BODY_KEYS.has(k))) {
      return json({ error: "bad-envelope" }, 400);
    }
    // Rebuild from allowlisted keys only; unknown keys / bad base64 /
    // bad lengths / v1 / weak KDF -> 400, nothing stored (#1, #2, #3).
    const envelope = rebuildEnvelope(body.envelope);
    if (!envelope) return json({ error: "bad-envelope" }, 400);
    const cid = body?.cid ?? null;
    if (cid !== null && !validCid(cid)) return json({ error: "bad-cid", cid }, 400);
    let id;
    if (body?.id !== undefined && body?.id !== null) {
      if (!isValidRecordId(body.id)) return json({ error: "bad-id" }, 400);
      id = body.id;
    } else {
      id = newRecordId();
    }
    const seq = body?.seq === undefined ? 0 : Number(body.seq);
    if (!Number.isInteger(seq) || seq < 0) return json({ error: "seq-invalid" }, 400);
    const now = new Date().toISOString();
    const row = {
      id,
      owner_id: did,
      cid,
      envelope: JSON.stringify(envelope),
      seq,
      created_at: now,
      updated_at: now,
    };
    const stored = await storeRecord(env, row);
    if (!stored.ok) {
      if (stored.error === "exists") return json({ error: "exists", id }, 409);
      return json({ error: "store-unavailable" }, 503);
    }
    return json(metadataOf(row), 201);
  }

  if (request.method === "GET" && path === "/records") {
    const did = requireDid(request);
    if (!did) return json({ error: "unauthorized" }, 401);
    let rows;
    try {
      rows = await listRecordsByOwner(env, did);
    } catch {
      return json({ error: "store-unavailable" }, 503);
    }
    return json({ items: rows.map(metadataOf) });
  }

  const recordMatch = path.match(/^\/records\/([^/]+)$/);
  if (request.method === "GET" && recordMatch) {
    const did = requireDid(request);
    if (!did) return json({ error: "unauthorized" }, 401);
    const id = safeDecode(recordMatch[1]);
    if (id === null) return json({ error: "bad-id" }, 400);
    let row;
    try {
      row = await fetchRecordById(env, id);
    } catch {
      return json({ error: "store-unavailable" }, 503);
    }
    // Missing OR owned by someone else -> 404 (existence is not leaked).
    if (!row || row.owner_id !== did) return json({ error: "not-found" }, 404);
    let envelope;
    try {
      envelope = JSON.parse(row.envelope);
    } catch {
      return json({ error: "not-found" }, 404);
    }
    return json({ ...metadataOf(row), envelope });
  }

  return json({ error: "not-found", path }, 404);
}

export default { fetch: fetchHandler };
