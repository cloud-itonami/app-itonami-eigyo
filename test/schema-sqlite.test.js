import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { fetchHandler } from "../src/worker.js";
import {
  canonicalAuthMessage,
  ed25519GenerateKeypair,
  ed25519Sign,
  pubkeyToDid,
} from "../src/auth.js";
import { sealPayload } from "../src/seal.js";

// Real-schema check: the fake D1 in fake-d1.js interprets SQL by string
// matching and cannot catch SQL typos. This test executes the Worker's
// actual statements against node:sqlite loaded with the real schema.sql
// (D1 is SQLite, so syntax/constraint errors here would fail on D1 too).
const synthetic = { name: "Synthetic Deal Alpha", amount: 12345 };
const PASS = "synthetic-schema-sqlite-passphrase";
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

// Minimal D1-shaped adapter over node:sqlite (prepare/bind/run/first/all/batch).
function sqliteD1() {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync(new URL("../schema.sql", import.meta.url), "utf8"));
  const wrap = (sql, params) => ({
    async run() {
      const info = db.prepare(sql).run(...params);
      return { success: true, meta: { changes: info.changes } };
    },
    async first() {
      return db.prepare(sql).get(...params) ?? null;
    },
    async all() {
      return { success: true, results: db.prepare(sql).all(...params) };
    },
  });
  return {
    _db: db,
    prepare(sql) { return { bind: (...params) => wrap(sql, params) }; },
    async batch(stmts) { return Promise.all(stmts.map((s) => s.run())); },
  };
}

describe("real schema (node:sqlite) — Worker SQL executes against schema.sql", () => {
  it("challenge->verify->records flow works on real SQLite, incl. atomic claim + seq retry", async () => {
    const db = sqliteD1(); // throws here if any schema.sql statement is invalid
    const env = { EIGYO_DB: db };
    const { seed, publicKey } = await ed25519GenerateKeypair();
    const did = pubkeyToDid(publicKey);
    const ch = await (await fetchHandler(req("POST", "/auth/challenge", { did }), env)).json();
    const signature = Buffer.from(
      await ed25519Sign(seed, new TextEncoder().encode(canonicalAuthMessage(ch))),
    ).toString("base64");
    const vf = await fetchHandler(req("POST", "/auth/verify", { did, nonce: ch.nonce, signature }), env);
    assert.equal(vf.status, 200);
    const { session } = await vf.json();
    // Replay of the same nonce fails on real SQLite too (atomic claim).
    const replay = await fetchHandler(req("POST", "/auth/verify", { did, nonce: ch.nonce, signature }), env);
    assert.equal(replay.status, 401);
    const auth = { did, session };
    // Seed a seq collision: counter at 0, row already at seq 1 -> first
    // insert violates UNIQUE(owner_id, seq) on real SQLite; retry wins.
    db._db.prepare("INSERT INTO owner_seq_counters (owner_id, seq) VALUES (?, 0)").run(did);
    db._db.prepare(
      "INSERT INTO sealed_records (id, owner_id, cid, envelope, seq, created_at, updated_at) VALUES (?, ?, NULL, ?, 1, '1970-01-01T00:00:00.000Z', '1970-01-01T00:00:00.000Z')",
    ).run("seeded-row-1", did, "{}");
    const envelope = await sealPayload(synthetic, PASS);
    const res = await fetchHandler(req("POST", "/records", { envelope }, auth), env);
    assert.equal(res.status, 201);
    assert.equal((await res.json()).seq, 2);
    // created_at indexes back the trim's oldest-first ordering.
    const idx = db._db.prepare(
      "SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'",
    ).all().map((r) => `${r.tbl_name}:${r.name}:${r.sql}`);
    assert.ok(idx.some((i) => i.startsWith("challenges:") && i.includes("created_at")), idx.join(" | "));
    assert.ok(idx.some((i) => i.startsWith("sessions:") && i.includes("created_at")), idx.join(" | "));
    // The schema really carries the UNIQUE(owner_id, seq) constraint.
    const cols = db._db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='sealed_records'").get();
    assert.ok(cols.sql.includes("UNIQUE(owner_id, seq)"), cols.sql);
  });
});
