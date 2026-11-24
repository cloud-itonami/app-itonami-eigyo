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
//   against the DID public key and issues a short-lived DID-bound session
//   (Bearer). Owner scope = the verified DID. The old role/userId
//   query-param trust is REMOVED — protected routes accept only a verified
//   session. Private keys, passphrases and KEKs never reach this Worker.
// - Missing objects answer 404, never 500 (cf. no-r2-yataverse-only.md);
//   bad CID -> 400 before any fetch runs.
//
// HTTP surface (see docs/sfa.md §7/§11):
//   GET  /health
//   GET  /ipfs/<cid>                       yataverse proxy (public)
//   POST /auth/challenge  {did}            -> 201 {nonce, purpose, timestamp} | 400
//   POST /auth/verify     {did, nonce, signature} -> 200 {token} | 401
//   POST /records         (auth) {id?, cid?, envelope, seq?} -> 201 metadata | 400 | 401 | 409
//   GET  /records         (auth)           -> 200 {items:[metadata...]} (own only)
//   GET  /records/:id     (auth)           -> 200 record | 404 | 401

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

function requireDid(request) {
  const header = request.headers?.get?.("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice("Bearer ".length).trim() : "";
  return authService.getSession(token);
}

function isSealedEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") return false;
  if (envelope.alg !== "AES-256-GCM") return false;
  if (typeof envelope.iv !== "string" || !envelope.iv) return false;
  if (typeof envelope.data !== "string" || !envelope.data) return false;
  if (envelope.v === 1) return true; // v1 stays storable until migration is done
  if (envelope.v !== 2) return false;
  const wk = envelope.wrappedKey;
  if (!wk || wk.alg !== "AES-256-GCM" || typeof wk.iv !== "string" || typeof wk.data !== "string") return false;
  const kdf = envelope.kdf;
  return !!kdf && kdf.name === "PBKDF2-HMAC-SHA256" &&
    Number.isInteger(kdf.iterations) && typeof kdf.salt === "string";
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
  } catch {
    return { ok: false, error: "exists" };
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
    return handleIpfs(decodeURIComponent(path.slice("/ipfs/".length)), fetchImpl);
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
    return json({ token: result.token, did: result.did, expiresAt: result.expiresAt });
  }

  if (request.method === "POST" && path === "/records") {
    const did = requireDid(request);
    if (!did) return json({ error: "unauthorized" }, 401);
    const body = await request.json().catch(() => null);
    if (!isSealedEnvelope(body?.envelope)) return json({ error: "bad-envelope" }, 400);
    const cid = body?.cid ?? null;
    if (cid !== null && !validCid(cid)) return json({ error: "bad-cid", cid }, 400);
    const id = body?.id ? String(body.id) : newRecordId();
    const seq = body?.seq === undefined ? 0 : Number(body.seq);
    if (!Number.isInteger(seq) || seq < 0) return json({ error: "seq-invalid" }, 400);
    const now = new Date().toISOString();
    const row = {
      id,
      owner_id: did,
      cid,
      envelope: JSON.stringify(body.envelope),
      seq,
      created_at: now,
      updated_at: now,
    };
    const stored = await storeRecord(env, row);
    if (!stored.ok) return json({ error: "exists", id }, 409);
    return json(metadataOf(row), 201);
  }

  if (request.method === "GET" && path === "/records") {
    const did = requireDid(request);
    if (!did) return json({ error: "unauthorized" }, 401);
    const rows = await listRecordsByOwner(env, did);
    return json({ items: rows.map(metadataOf) });
  }

  const recordMatch = path.match(/^\/records\/([^/]+)$/);
  if (request.method === "GET" && recordMatch) {
    const did = requireDid(request);
    if (!did) return json({ error: "unauthorized" }, 401);
    const row = await fetchRecordById(env, decodeURIComponent(recordMatch[1]));
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
