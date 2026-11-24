import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { fetchHandler } from "../src/worker.js";
import {
  canonicalAuthMessage,
  ed25519GenerateKeypair,
  ed25519Sign,
  pubkeyToDid,
} from "../src/auth.js";
import { sealPayload } from "../src/seal.js";
import { createFakeD1 } from "./fake-d1.js";

// Synthetic data only.
const synthetic = {
  name: "Synthetic Deal Alpha",
  amount: 12345,
  probability: 60,
  stage: "negotiation",
  account: "Synthetic Co 000",
};
const PASS = "synthetic-d1-auth-test-passphrase";
const base = "http://localhost";
const req = (method, path, body, auth) =>
  new Request(base + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(auth ? { "x-did": auth.did, "x-session": auth.session } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
const json = (res) => res.json();

async function identity() {
  const { seed, publicKey } = await ed25519GenerateKeypair();
  return { seed, did: pubkeyToDid(publicKey) };
}
async function signFor(seed, challenge) {
  const msg = canonicalAuthMessage({
    nonce: challenge.nonce,
    purpose: challenge.purpose,
    timestamp: challenge.timestamp,
  });
  return Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(msg))).toString("base64");
}
async function doChallenge(db, did) {
  const res = await fetchHandler(req("POST", "/auth/challenge", { did }), { EIGYO_DB: db });
  assert.equal(res.status, 201, `challenge for ${did} should be 201`);
  return json(res);
}
async function makeSession(db) {
  const idn = await identity();
  const challenge = await doChallenge(db, idn.did);
  const signature = await signFor(idn.seed, challenge);
  const res = await fetchHandler(
    req("POST", "/auth/verify", { did: idn.did, nonce: challenge.nonce, signature }),
    { EIGYO_DB: db },
  );
  assert.equal(res.status, 200);
  const verified = await json(res);
  return { ...idn, session: verified.session, env: { EIGYO_DB: db } };
}
async function sha256Hex(text) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("D1 auth store — negative controls (a)-(f)", () => {
  it("negative control a: two Worker instances, same signature in parallel -> exactly 1 session", async () => {
    const db = createFakeD1();
    const idn = await identity();
    const challenge = await doChallenge(db, idn.did);
    const signature = await signFor(idn.seed, challenge);
    const body = { did: idn.did, nonce: challenge.nonce, signature };
    const [r1, r2] = await Promise.all([
      fetchHandler(req("POST", "/auth/verify", body), { EIGYO_DB: db }),
      fetchHandler(req("POST", "/auth/verify", body), { EIGYO_DB: db }),
    ]);
    const statuses = [r1.status, r2.status].sort();
    assert.deepEqual(statuses, [200, 401]);
    assert.equal(db._tables.sessions.size, 1);
    const okRes = r1.status === 200 ? r1 : r2;
    assert.ok((await json(okRes)).session);
  });

  it("negative control b: expired nonce -> rejected (401)", async () => {
    const db = createFakeD1();
    const idn = await identity();
    const challenge = await doChallenge(db, idn.did);
    const signature = await signFor(idn.seed, challenge);
    // Force the stored challenge past its expiry.
    for (const row of db._tables.challenges.values()) row.expires_at = Date.now() - 1;
    const res = await fetchHandler(
      req("POST", "/auth/verify", { did: idn.did, nonce: challenge.nonce, signature }),
      { EIGYO_DB: db },
    );
    assert.equal(res.status, 401);
    assert.equal(db._tables.sessions.size, 0);
  });

  it("negative control c: wrong DID -> rejected (401) and nonce burned", async () => {
    const db = createFakeD1();
    const a = await identity();
    const b = await identity();
    const challenge = await doChallenge(db, a.did);
    const signatureB = await signFor(b.seed, challenge);
    const res = await fetchHandler(
      req("POST", "/auth/verify", { did: b.did, nonce: challenge.nonce, signature: signatureB }),
      { EIGYO_DB: db },
    );
    assert.equal(res.status, 401);
    // Even the rightful DID can no longer use the burned nonce.
    const signatureA = await signFor(a.seed, challenge);
    const retry = await fetchHandler(
      req("POST", "/auth/verify", { did: a.did, nonce: challenge.nonce, signature: signatureA }),
      { EIGYO_DB: db },
    );
    assert.equal(retry.status, 401);
    assert.equal(db._tables.sessions.size, 0);
  });

  it("negative control d: no EIGYO_DB binding -> 503 (challenge/verify/records), never memory fallback", async () => {
    const ch = await fetchHandler(req("POST", "/auth/challenge", { did: "did:key:z0" }), {});
    assert.equal(ch.status, 503);
    assert.deepEqual(await json(ch), { error: "store-unavailable" });
    const vf = await fetchHandler(req("POST", "/auth/verify", { did: "x", nonce: "y", signature: "z" }), {});
    assert.equal(vf.status, 503);
    const rec = await fetchHandler(
      req("POST", "/records", { envelope: { v: 2 } }, { did: "x", session: "y" }),
      {},
    );
    assert.equal(rec.status, 503);
    const list = await fetchHandler(req("GET", "/records", undefined, { did: "x", session: "y" }), {});
    assert.equal(list.status, 503);
    const one = await fetchHandler(req("GET", "/records/someid", undefined, { did: "x", session: "y" }), {});
    assert.equal(one.status, 503);
    // Public routes need no binding.
    assert.equal((await fetchHandler(req("GET", "/health"), {})).status, 200);
  });

  it("negative control e: DB contains 0 raw nonce/session values (hash-only proof)", async () => {
    const db = createFakeD1();
    const idn = await identity();
    const challenge = await doChallenge(db, idn.did);
    const signature = await signFor(idn.seed, challenge);
    const res = await fetchHandler(
      req("POST", "/auth/verify", { did: idn.did, nonce: challenge.nonce, signature }),
      { EIGYO_DB: db },
    );
    assert.equal(res.status, 200);
    const { session } = await json(res);
    const dump = db._dump();
    assert.equal(dump.includes(challenge.nonce), false, "raw nonce must not be in DB");
    assert.equal(dump.includes(session), false, "raw session must not be in DB");
    assert.ok(dump.includes(await sha256Hex(challenge.nonce)), "nonce_hash stored");
    assert.ok(dump.includes(await sha256Hex(session)), "session_hash stored");
    for (const row of db._tables.challenges.values()) {
      assert.deepEqual(Object.keys(row).sort(), ["created_at", "did", "expires_at", "nonce_hash", "purpose", "timestamp", "used"]);
    }
    for (const row of db._tables.sessions.values()) {
      assert.deepEqual(Object.keys(row).sort(), ["created_at", "did", "expires_at", "session_hash"]);
    }
  });

  it("negative control f: DB contains 0 plaintext payload fields (envelope ciphertext only)", async () => {
    const db = createFakeD1();
    const { did, session } = await makeSession(db);
    const envelope = await sealPayload(synthetic, PASS);
    const res = await fetchHandler(
      req("POST", "/records", { envelope, cid: "bafy-synthetic-cid" }, { did, session }),
      { EIGYO_DB: db },
    );
    assert.equal(res.status, 201);
    const dump = db._dump();
    assert.equal(dump.includes(synthetic.name), false);
    assert.equal(dump.includes(synthetic.account), false);
    const row = [...db._tables.sealed_records.values()][0];
    assert.deepEqual(Object.keys(row).sort(), ["cid", "created_at", "envelope", "id", "owner_id", "seq", "updated_at"]);
  });
});

describe("D1 auth store — single-use, sweep, seq", () => {
  it("a failed signature burns the nonce (good signature afterwards still 401)", async () => {
    const db = createFakeD1();
    const idn = await identity();
    const challenge = await doChallenge(db, idn.did);
    const bad = Buffer.from(await ed25519Sign(idn.seed, new TextEncoder().encode("x||y||z"))).toString("base64");
    const first = await fetchHandler(
      req("POST", "/auth/verify", { did: idn.did, nonce: challenge.nonce, signature: bad }),
      { EIGYO_DB: db },
    );
    assert.equal(first.status, 401);
    const good = await signFor(idn.seed, challenge);
    const second = await fetchHandler(
      req("POST", "/auth/verify", { did: idn.did, nonce: challenge.nonce, signature: good }),
      { EIGYO_DB: db },
    );
    assert.equal(second.status, 401);
    assert.equal(db._tables.sessions.size, 0);
  });

  it("no DID caps: third party issuing many challenges for the victim DID still lets the victim in", async () => {
    const db = createFakeD1();
    const victim = await identity();
    // 30 challenges issued for the victim DID (old per-DID cap was 10).
    for (let i = 0; i < 30; i++) await doChallenge(db, victim.did);
    // The victim can still obtain a fresh challenge and log in.
    const challenge = await doChallenge(db, victim.did);
    const signature = await signFor(victim.seed, challenge);
    const res = await fetchHandler(
      req("POST", "/auth/verify", { did: victim.did, nonce: challenge.nonce, signature }),
      { EIGYO_DB: db },
    );
    assert.equal(res.status, 200);
  });

  it("no global cap: 400 disposable-DID challenges do not block a new user", async () => {
    const db = createFakeD1();
    const now = Date.now();
    for (let i = 0; i < 400; i++) {
      db._tables.challenges.set(`disposable-${i}`, {
        nonce_hash: `disposable-${i}`, did: `did:key:zdisposable${i}`, purpose: "eigyo:auth:login",
        timestamp: new Date(now).toISOString(), expires_at: now + 60_000, used: 0, created_at: now + i,
      });
    }
    const fresh = await identity();
    const challenge = await doChallenge(db, fresh.did);
    assert.ok(challenge.nonce);
    // The seeded rows are untouched by the new issuance (no rejection, no trim below cap).
    assert.equal(db._tables.challenges.size, 401);
  });

  it("rate limit binding rejection passes through as 429 (Worker does not count DIDs)", async () => {
    const db = createFakeD1();
    const idn = await identity();
    let seenKey = null;
    const denying = { limit: async ({ key }) => { seenKey = key; return { success: false }; } };
    const res = await fetchHandler(
      new Request(base + "/auth/challenge", {
        method: "POST",
        headers: { "content-type": "application/json", "cf-connecting-ip": "203.0.113.7" },
        body: JSON.stringify({ did: idn.did }),
      }),
      { EIGYO_DB: db, AUTH_RATE_LIMIT: denying },
    );
    assert.equal(res.status, 429);
    assert.equal(seenKey, "203.0.113.7"); // keyed by client IP, never by DID
    // An allowing binding lets the request through.
    const allowing = { limit: async () => ({ success: true }) };
    const ok = await fetchHandler(req("POST", "/auth/challenge", { did: idn.did }), { EIGYO_DB: db, AUTH_RATE_LIMIT: allowing });
    assert.equal(ok.status, 201);
  });

  it("x-forwarded-for alone is not used as the rate-limit key (binding not called without cf-connecting-ip)", async () => {
    const db = createFakeD1();
    const idn = await identity();
    let calls = 0;
    const spy = { limit: async () => { calls++; return { success: true }; } };
    const res = await fetchHandler(
      new Request(base + "/auth/challenge", {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": "198.51.100.9" },
        body: JSON.stringify({ did: idn.did }),
      }),
      { EIGYO_DB: db, AUTH_RATE_LIMIT: spy },
    );
    assert.equal(res.status, 201); // no cf-connecting-ip -> no limit, issuance proceeds
    assert.equal(calls, 0); // x-forwarded-for is spoofable: never used as key
  });

  it("under the row cap, trim deletes nothing", async () => {
    const db = createFakeD1();
    const now = Date.now();
    for (let i = 0; i < 5; i++) {
      db._tables.challenges.set(`keep-${i}`, {
        nonce_hash: `keep-${i}`, did: `did:key:zkeep${i}`, purpose: "eigyo:auth:login",
        timestamp: new Date(now).toISOString(), expires_at: now + 60_000, used: 0, created_at: now + i,
      });
    }
    const idn = await identity();
    await doChallenge(db, idn.did);
    for (let i = 0; i < 5; i++) assert.ok(db._tables.challenges.has(`keep-${i}`), `keep-${i} must survive`);
    assert.equal(db._tables.challenges.size, 6);
  });

  it("no rate limit binding: challenge issuance works without limits (absence is logged)", async () => {
    const db = createFakeD1();
    const idn = await identity();
    const res = await fetchHandler(req("POST", "/auth/challenge", { did: idn.did }), { EIGYO_DB: db });
    assert.equal(res.status, 201);
  });

  it("table trim: beyond 10,000 challenge rows the oldest are deleted, never rejected", async () => {
    const db = createFakeD1();
    const now = Date.now();
    for (let i = 0; i < 10_001; i++) {
      db._tables.challenges.set(`old-${i}`, {
        nonce_hash: `old-${i}`, did: `did:key:zold${i}`, purpose: "eigyo:auth:login",
        timestamp: new Date(now - 30_000).toISOString(), expires_at: now + 60_000, used: 0, created_at: now - 30_000 + i,
      });
    }
    const idn = await identity();
    await doChallenge(db, idn.did);
    assert.ok(db._tables.challenges.size <= 10_001, `trimmed to cap, got ${db._tables.challenges.size}`);
    assert.equal(db._tables.challenges.has("old-0"), false); // oldest first
  });

  it("expiry sweep: expired challenges/sessions are deleted on the challenge path", async () => {
    const db = createFakeD1();
    const now = Date.now();
    db._tables.challenges.set("expired-1", {
      nonce_hash: "expired-1", did: "did:key:zold", purpose: "eigyo:auth:login",
      timestamp: new Date(now - 600_000).toISOString(), expires_at: now - 1, used: 0, created_at: now - 600_000,
    });
    db._tables.sessions.set("expired-2", { session_hash: "expired-2", did: "did:key:zold", expires_at: now - 1, created_at: now - 600_000 });
    const idn = await identity();
    await doChallenge(db, idn.did);
    assert.equal(db._tables.challenges.has("expired-1"), false);
    assert.equal(db._tables.sessions.has("expired-2"), false);
  });

  it("parallel same-owner record writes get distinct server-allocated seqs", async () => {
    const db = createFakeD1();
    const { did, session } = await makeSession(db);
    const auth = { did, session };
    const e1 = await sealPayload(synthetic, PASS);
    const e2 = await sealPayload({ ...synthetic, name: "Synthetic Deal Beta" }, PASS);
    const [r1, r2] = await Promise.all([
      fetchHandler(req("POST", "/records", { envelope: e1 }, auth), { EIGYO_DB: db }),
      fetchHandler(req("POST", "/records", { envelope: e2 }, auth), { EIGYO_DB: db }),
    ]);
    assert.equal(r1.status, 201);
    assert.equal(r2.status, 201);
    const m1 = await json(r1);
    const m2 = await json(r2);
    assert.notEqual(m1.seq, m2.seq);
    const rows = [...db._tables.sealed_records.values()];
    assert.equal(new Set(rows.map((r) => r.seq)).size, rows.length);
  });

  it("UNIQUE(owner_id, seq) collision is retried to a fresh seq (201, no duplicate)", async () => {
    const db = createFakeD1();
    const { did, session } = await makeSession(db);
    // Simulate a counter that must catch up: a row already occupies seq 1
    // while the counter still hands out 1 -> the first insert collides.
    db._tables.sealed_records.set("seeded-seq-1", {
      id: "seeded-seq-1", owner_id: did, cid: null, envelope: "{}", seq: 1,
      created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
    });
    db._tables.owner_seq_counters.set(did, { owner_id: did, seq: 0 });
    const envelope = await sealPayload(synthetic, PASS);
    const res = await fetchHandler(
      req("POST", "/records", { envelope }, { did, session }),
      { EIGYO_DB: db },
    );
    assert.equal(res.status, 201);
    const meta = await json(res);
    assert.equal(meta.seq, 2);
    assert.equal(new Set([...db._tables.sealed_records.values()].map((r) => r.seq)).size, 2);
  });

  it("expired session in D1 -> 401 on protected route", async () => {
    const db = createFakeD1();
    const { did, session } = await makeSession(db);
    for (const row of db._tables.sessions.values()) row.expires_at = Date.now() - 1;
    const res = await fetchHandler(req("GET", "/records", undefined, { did, session }), { EIGYO_DB: db });
    assert.equal(res.status, 401);
  });
});
