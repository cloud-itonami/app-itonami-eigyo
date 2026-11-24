import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fetchHandler } from "../src/worker.js";
import {
  canonicalAuthMessage,
  createAuthService,
  didToPubkey,
  ed25519GenerateKeypair,
  ed25519PublicKeyFromSeed,
  ed25519Sign,
  ed25519Verify,
  isSmallOrderEncoding,
  pubkeyToDid,
} from "../src/auth.js";
import { openPayload, rewrapPayload, sealPayload } from "../src/seal.js";
import { createFakeD1 } from "./fake-d1.js";

// Shared fake D1 for HTTP tests: challenge/session/record state lives in
// D1 now, so every auth+records call in a test flow MUST pass this env
// (previously calls passed {} and used the isolate-local memory stores).
const sharedDb = createFakeD1();
const env = { EIGYO_DB: sharedDb };

// Synthetic data only — no real opportunity/customer data in this repo.
const synthetic = {
  name: "Synthetic Deal Alpha",
  amount: 12345,
  probability: 60,
  stage: "negotiation",
  account: "Synthetic Co 000",
};
const PASS = "synthetic-worker-test-passphrase";

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
const rawReq = (method, path, body, headers) =>
  new Request(base + path, {
    method,
    headers: { "content-type": "application/json", ...(headers || {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

async function json(res) {
  return res.json();
}

// Full client flow: generate keypair -> challenge -> sign -> verify -> session.
async function makeSession(db = sharedDb) {
  const { seed, publicKey } = await ed25519GenerateKeypair();
  const did = pubkeyToDid(publicKey);
  const localEnv = { EIGYO_DB: db };
  const challengeRes = await fetchHandler(req("POST", "/auth/challenge", { did }), localEnv);
  assert.equal(challengeRes.status, 201);
  const challenge = await json(challengeRes);
  const message = canonicalAuthMessage({
    nonce: challenge.nonce,
    purpose: challenge.purpose,
    timestamp: challenge.timestamp,
  });
  const signature = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(message))).toString("base64");
  const verifyRes = await fetchHandler(req("POST", "/auth/verify", { did, nonce: challenge.nonce, signature }), localEnv);
  assert.equal(verifyRes.status, 200);
  const verified = await json(verifyRes);
  assert.ok(verified.session);
  return { seed, did, session: verified.session };
}

describe("ed25519 WebCrypto vs RFC 8032 vectors + native Node Ed25519 (#4)", () => {
  const fromHex = (h) => new Uint8Array(Buffer.from(h, "hex"));
  const hex = (b) => Buffer.from(b).toString("hex");
  // RFC 8032 Section 7.1 (seed, pubkey, msg, sig).
  const RFC = [
    {
      seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      pub: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      msg: "",
      sig: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
      seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      pub: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      msg: "72",
      sig: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69" +
        "da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
      seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      pub: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      msg: "af82",
      sig: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac" +
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
  ];

  it("reproduces RFC pubkeys + signatures exactly and rejects tampering", async () => {
    for (const v of RFC) {
      const seed = fromHex(v.seed);
      assert.equal(hex(await ed25519PublicKeyFromSeed(seed)), v.pub);
      assert.equal(hex(await ed25519Sign(seed, fromHex(v.msg))), v.sig);
      assert.equal(await ed25519Verify(fromHex(v.pub), fromHex(v.msg), fromHex(v.sig)), true);
      const bad = fromHex(v.sig);
      bad[40] ^= 0x01;
      assert.equal(await ed25519Verify(fromHex(v.pub), fromHex(v.msg), bad), false);
      assert.equal(await ed25519Verify(fromHex(v.pub), fromHex("deadbeef"), fromHex(v.sig)), false);
    }
  });

  it("agrees with native Node Ed25519 (ours->node and node->ours)", async () => {
    const { createPrivateKey, createPublicKey, sign, verify } = await import("node:crypto");
    for (const msgHex of ["", "00", "0123456789abcdef", "736f6d652073796e746865746963206d657373616765"]) {
      const { seed, publicKey } = await ed25519GenerateKeypair();
      const msg = fromHex(msgHex);
      const ours = await ed25519Sign(seed, msg);
      const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]);
      const priv = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
      const pub = createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(-32);
      assert.equal(hex(pub), hex(publicKey));
      assert.equal(verify(null, Buffer.from(msg), createPublicKey(priv), Buffer.from(ours)), true);
      assert.equal(await ed25519Verify(publicKey, msg, new Uint8Array(sign(null, Buffer.from(msg), priv))), true);
    }
  });
});

describe("did:key", () => {
  it("round-trips and rejects malformed dids", async () => {
    const { publicKey } = await ed25519GenerateKeypair();
    const did = pubkeyToDid(publicKey);
    assert.ok(did.startsWith("did:key:z"));
    assert.equal(Buffer.from(didToPubkey(did)).toString("hex"), Buffer.from(publicKey).toString("hex"));
    for (const bad of ["did:key:z!!!", "did:web:example.com", "did:key:z"]) {
      assert.throws(() => didToPubkey(bad));
    }
  });
});

describe("auth service (challenge/verify/session, unit)", () => {
  it("rejects nonce replay, expiry, and wrong signatures", async () => {
    let t = 1_000_000;
    const auth = createAuthService({ now: () => t, db: createFakeD1() });
    assert.deepEqual((await auth.issueChallenge("did:key:z0")).ok, false);
    const { seed, publicKey } = await ed25519GenerateKeypair();
    const did = pubkeyToDid(publicKey);
    const c = await auth.issueChallenge(did);
    const msg = canonicalAuthMessage({ nonce: c.nonce, purpose: c.purpose, timestamp: c.timestamp });
    const good = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(msg))).toString("base64");
    const wrong = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode("x||y||z"))).toString("base64");
    // wrong signature -> 401 shape, nonce consumed
    assert.deepEqual(await auth.verifyResponse({ did, nonce: c.nonce, signature: wrong }), {
      ok: false,
      error: "auth-failed",
    });
    assert.deepEqual(await auth.verifyResponse({ did, nonce: c.nonce, signature: good }), {
      ok: false,
      error: "auth-failed",
    });
    // expired nonce -> auth-failed
    t = 1_000_000;
    const c2 = await auth.issueChallenge(did);
    const msg2 = canonicalAuthMessage({ nonce: c2.nonce, purpose: c2.purpose, timestamp: c2.timestamp });
    const sig2 = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(msg2))).toString("base64");
    t += 5 * 60 * 1000 + 1;
    assert.deepEqual(await auth.verifyResponse({ did, nonce: c2.nonce, signature: sig2 }), {
      ok: false,
      error: "auth-failed",
    });
    // valid -> session -> expired session
    t = 1_000_000;
    const c3 = await auth.issueChallenge(did);
    const msg3 = canonicalAuthMessage({ nonce: c3.nonce, purpose: c3.purpose, timestamp: c3.timestamp });
    const sig3 = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(msg3))).toString("base64");
    const verified = await auth.verifyResponse({ did, nonce: c3.nonce, signature: sig3 });
    assert.equal(verified.ok, true);
    assert.equal(await auth.getSession(verified.session, did), did);
    assert.equal(await auth.getSession(verified.session, "did:key:zOther"), null);
    t += 5 * 60 * 1000 + 1;
    assert.equal(await auth.getSession(verified.session, did), null);
  });
});

describe("worker http surface", () => {
  it("serves health with yataverse storage flag", async () => {
    const res = await fetchHandler(req("GET", "/health"), env);
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.deepEqual(body, { ok: true, service: "app-itonami-eigyo", storage: "yataverse", r2: false });
  });

  it("auth: challenge/verify over HTTP; bad did 400; bad sig 401; no session = 401", async () => {
    const badDid = await fetchHandler(req("POST", "/auth/challenge", { did: "did:key:z0" }), env);
    assert.equal(badDid.status, 400);

    const { seed, publicKey } = await ed25519GenerateKeypair();
    const did = pubkeyToDid(publicKey);
    const ch = await json(await fetchHandler(req("POST", "/auth/challenge", { did }), env));
    const wrongSig = Buffer.from(
      await ed25519Sign(seed, new TextEncoder().encode("nonce||purpose||timestamp")),
    ).toString("base64");
    const wrong = await fetchHandler(req("POST", "/auth/verify", { did, nonce: ch.nonce, signature: wrongSig }), env);
    assert.equal(wrong.status, 401);
    assert.deepEqual(await json(wrong), { error: "auth-failed" });

    const meh = await fetchHandler(req("GET", "/records"), env);
    assert.equal(meh.status, 401);
    assert.deepEqual(await json(meh), { error: "unauthorized" });
  });

  it("sealed records: end-to-end seal -> store -> fetch -> open (negative-control a)", async () => {
    const { did, session } = await makeSession();
    const auth = { did, session };
    const envelope = await sealPayload(synthetic, PASS);
    const created = await fetchHandler(
      req("POST", "/records", { id: "11111111-1111-4111-8111-111111111111", envelope, cid: "bafy-synthetic-cid", seq: 1 }, auth),
      env,
    );
    assert.equal(created.status, 201);
    const meta = await json(created);
    assert.equal(meta.owner_id, did);
    assert.equal(meta.cid, "bafy-synthetic-cid");
    assert.equal(meta.envelope, undefined); // metadata only
    assert.equal(JSON.stringify(meta).includes("Synthetic"), false);

    const fetched = await fetchHandler(req("GET", "/records/11111111-1111-4111-8111-111111111111", undefined, auth), env);
    assert.equal(fetched.status, 200);
    const record = await json(fetched);
    assert.deepEqual(await openPayload(record.envelope, PASS), synthetic);

    const listed = await fetchHandler(req("GET", "/records", undefined, auth), env);
    const items = (await json(listed)).items;
    assert.ok(items.some((r) => r.id === "11111111-1111-4111-8111-111111111111"));
    assert.ok(items.every((r) => r.envelope === undefined)); // list never leaks envelopes
  });

  it("sealed records: owner scoping, bad envelope/cid/seq, duplicates", async () => {
    const a = await makeSession();
    const b = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    await fetchHandler(req("POST", "/records", { id: "22222222-2222-4222-8222-222222222222", envelope }, a), env);
    // other owner -> 404 (existence not leaked), missing -> 404 never 500
    assert.equal((await fetchHandler(req("GET", "/records/22222222-2222-4222-8222-222222222222", undefined, b), env)).status, 404);
    const missing = await fetchHandler(req("GET", "/records/nope", undefined, a), env);
    assert.equal(missing.status, 404);
    assert.notEqual(missing.status, 500);
    // bad envelope / bad cid / bad seq / duplicate
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope: { v: 2 } }, a), env)).status,
      400,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope, cid: "a/b" }, a), env)).status,
      400,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope, seq: -1 }, a), env)).status,
      400,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { id: "22222222-2222-4222-8222-222222222222", envelope }, a), env)).status,
      409,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope, cid: "bad cid" }, a), env)).status,
      400,
    );
  });

  it("plaintext routes are removed (server-side search/report gone by design)", async () => {
    const auth = await makeSession();
    assert.equal((await fetchHandler(req("GET", "/opportunities", undefined, auth), env)).status, 404);
    assert.equal((await fetchHandler(req("POST", "/opportunities", { name: "X" }, auth), env)).status, 404);
    assert.equal((await fetchHandler(req("GET", "/report", undefined, auth), env)).status, 404);
    assert.equal((await fetchHandler(req("GET", "/accounts", undefined, auth), env)).status, 404);
  });
});

describe("EIGYO_DB (D1) wiring via fake D1", () => {
  it("stores/fetches sealed_records via env.EIGYO_DB (ciphertext only)", async () => {
    const db = createFakeD1();
    const localEnv = { EIGYO_DB: db };
    const { did, session } = await makeSession(db);
    const auth = { did, session };
    const envelope = await sealPayload(synthetic, PASS);
    const created = await fetchHandler(req("POST", "/records", { id: "33333333-3333-4333-8333-333333333333", envelope }, auth), localEnv);
    assert.equal(created.status, 201);
    const row = db._tables.sealed_records.get("33333333-3333-4333-8333-333333333333");
    assert.ok(row);
    assert.equal(row.owner_id, did);
    const storedText = JSON.stringify(row);
    assert.equal(storedText.includes(synthetic.name), false);
    assert.equal(storedText.includes("Synthetic Co 000"), false);

    const fetched = await fetchHandler(req("GET", "/records/33333333-3333-4333-8333-333333333333", undefined, auth), localEnv);
    assert.equal(fetched.status, 200);
    assert.deepEqual(await openPayload((await json(fetched)).envelope, PASS), synthetic);
    const listed = await json(await fetchHandler(req("GET", "/records", undefined, auth), localEnv));
    assert.ok(listed.items.some((r) => r.id === "33333333-3333-4333-8333-333333333333"));
    assert.ok(listed.items.every((r) => r.envelope === undefined));
  });
});

describe("yataverse proxy (contracts preserved)", () => {
  it("streams upstream body with content-type; missing/error -> 404 never 500", async () => {
    const okFetch = async () =>
      new Response("blob-bytes", { status: 200, headers: { "content-type": "image/png" } });
    const res = await fetchHandler(req("GET", "/ipfs/bafy-cid"), env, okFetch);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "image/png");
    assert.equal(res.headers.get("cache-control"), "public, max-age=300");
    assert.equal(await res.text(), "blob-bytes");

    const missingFetch = async () => new Response("nope", { status: 404 });
    const missing = await fetchHandler(req("GET", "/ipfs/bafy-cid"), env, missingFetch);
    assert.equal(missing.status, 404);
    assert.notEqual(missing.status, 500);

    const throwFetch = async () => {
      throw new Error("network down");
    };
    const unreachable = await fetchHandler(req("GET", "/ipfs/bafy-cid"), env, throwFetch);
    assert.equal(unreachable.status, 404);
    assert.notEqual(unreachable.status, 500);
  });

  it("rejects bad CIDs with 400 before any fetch", async () => {
    let fetched = false;
    const spyFetch = async () => {
      fetched = true;
      return new Response("x");
    };
    for (const bad of ["", "..x", "a%2Fb", "%5C", "a%20b", "b%00ad"]) {
      const res = await fetchHandler(req("GET", `/ipfs/${bad}`), env, spyFetch);
      assert.equal(res.status, 400, `expected 400 for CID ${bad}`);
    }
    assert.equal(fetched, false);
  });
});

describe("R2 non-dependence + schema (negative-control f) + no key material (e)", () => {
  function stripComments(src) {
    return src
      .split("\n")
      .map((line) => line.replace(/\/\/.*$/, ""))
      .join("\n")
      .replace(/\/\*[\s\S]*?\*\//g, "");
  }

  it("wrangler.jsonc carries no r2 bucket binding; sources never call R2", () => {
    const wrangler = readFileSync(new URL("../wrangler.jsonc", import.meta.url), "utf8");
    assert.equal(wrangler.includes('"r2_buckets"'), false);
    assert.equal(wrangler.includes("00000000-0000-0000-0000-000000000000"), true); // placeholder kept
    for (const file of ["src/sfa.js", "src/worker.js", "src/seal.js", "src/auth.js"]) {
      const code = stripComments(readFileSync(new URL(`../${file}`, import.meta.url), "utf8"));
      assert.equal(code.includes("R2."), false, `${file} must not reference R2.`);
      assert.equal(code.includes("r2_buckets"), false, `${file} must not reference r2_buckets`);
    }
  });

  it("schema.sql has sealed_records only and no plaintext columns", () => {
    const schema = readFileSync(new URL("../schema.sql", import.meta.url), "utf8");
    assert.ok(schema.includes("CREATE TABLE sealed_records"));
    assert.ok(schema.includes("CREATE INDEX idx_sealed_owner"));
    assert.equal(schema.includes("CREATE TABLE accounts"), false);
    assert.equal(schema.includes("CREATE TABLE opportunities"), false);
    // grep -nE 'name|amount|probability|stage' schema.sql must print nothing
    const hits = schema.split("\n").filter((line) => /name|amount|probability|stage/.test(line));
    assert.deepEqual(hits, []);
  });

  it("no key material / plaintext paths in sources (grep-empty)", () => {
    const files = ["src/seal.js", "src/worker.js", "src/auth.js", "schema.sql", "wrangler.jsonc"];
    for (const file of files) {
      const raw = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
      const src = stripComments(raw);
      assert.equal(/-----BEGIN/.test(raw), false, `${file} must not contain key blocks`);
      assert.equal(/console\.log/.test(raw), false, `${file} must not log`);
      assert.equal(/(passphrase|password|seed)\s*[:=]\s*['"][^'"]{8,}['"]/i.test(src), false, `${file} must not assign secret literals`);
      assert.equal(/searchParams\.get\("role"\)|searchParams\.get\("userId"\)|userId/.test(src), false, `${file} must not trust role/userId params`);
    }
  });
});

describe("review #1: server rejects plaintext / unknown keys / bad base64+lengths / bad id", () => {
  it("rejects the Organizer plaintext payload with 400 and stores nothing", async () => {
    const auth = await makeSession();
    const res = await fetchHandler(
      req("POST", "/records", {
        id: "Acme Corp deal",
        envelope: { v: 1, alg: "AES-256-GCM", iv: "x", data: "PLAINTEXT Acme", name: "PLAINTEXT extra" },
      }, auth),
      env,
    );
    assert.equal(res.status, 400);
    assert.equal((await json(res)).error, "bad-envelope");
    assert.equal((await fetchHandler(req("GET", "/records/Acme%20Corp%20deal", undefined, auth), env)).status, 404);
  });
  it("rejects unknown envelope/wrappedKey/kdf keys and non-allowlisted body keys", async () => {
    const auth = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    assert.equal((await fetchHandler(req("POST", "/records", { envelope: { ...envelope, name: "PLAINTEXT extra" } }, auth), env)).status, 400);
    assert.equal((await fetchHandler(req("POST", "/records", { envelope: { ...envelope, wrappedKey: { ...envelope.wrappedKey, extra: "x" } } }, auth), env)).status, 400);
    assert.equal((await fetchHandler(req("POST", "/records", { envelope: { ...envelope, kdf: { ...envelope.kdf, extra: 1 } } }, auth), env)).status, 400);
    assert.equal((await fetchHandler(req("POST", "/records", { envelope, name: "PLAINTEXT" }, auth), env)).status, 400);
  });
  it("rejects bad base64 and wrong field lengths (iv/salt/wrapped/data)", async () => {
    const auth = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    const b64 = (n) => Buffer.alloc(n, 7).toString("base64");
    const cases = [
      { ...envelope, iv: "!!not-base64!!" },
      { ...envelope, iv: b64(8) },
      { ...envelope, data: b64(4) },
      { ...envelope, wrappedKey: { ...envelope.wrappedKey, iv: b64(16) } },
      { ...envelope, wrappedKey: { ...envelope.wrappedKey, data: b64(32) } },
      { ...envelope, kdf: { ...envelope.kdf, salt: b64(8) } },
    ];
    for (const envCase of cases) {
      assert.equal((await fetchHandler(req("POST", "/records", { envelope: envCase }, auth), env)).status, 400);
    }
  });
  it("rejects ids that are neither server-issued (record_<32hex>) nor UUID", async () => {
    const auth = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    for (const badId of ["Acme Corp deal", "record_alpha", "plain-id", "123"]) {
      assert.equal((await fetchHandler(req("POST", "/records", { id: badId, envelope }, auth), env)).status, 400, `bad id ${badId}`);
    }
    assert.equal((await fetchHandler(req("POST", "/records", { id: `record_${"a".repeat(32)}`, envelope }, auth), env)).status, 201);
    assert.equal((await fetchHandler(req("POST", "/records", { id: "44444444-4444-4444-8444-444444444444", envelope }, auth), env)).status, 201);
    const generated = await fetchHandler(req("POST", "/records", { envelope }, auth), env);
    assert.equal(generated.status, 201);
    assert.match((await json(generated)).id, /^record_[0-9a-f]{32}$/);
  });
});

describe("review #2: POST /records accepts v2 only (v1 rejected)", () => {
  it("rejects a well-formed v1 envelope on POST /records with 400", async () => {
    const { sealPayloadV1, newKey } = await import("../src/seal.js");
    const auth = await makeSession();
    const v1 = await sealPayloadV1(synthetic, await newKey());
    assert.equal(v1.v, 1);
    assert.equal((await fetchHandler(req("POST", "/records", { envelope: v1 }, auth), env)).status, 400);
  });
});

describe("review #3: KDF 600,000 + salt 16B enforced server-side", () => {
  it("rejects iterations:1 / empty salt / iterations:30000000 with 400", async () => {
    const auth = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    const cases = [
      { ...envelope, kdf: { ...envelope.kdf, iterations: 1 } },
      { ...envelope, kdf: { ...envelope.kdf, salt: "" } },
      { ...envelope, kdf: { ...envelope.kdf, iterations: 30000000 } },
      { ...envelope, kdf: { ...envelope.kdf, iterations: 599999 } },
    ];
    for (const envCase of cases) {
      assert.equal((await fetchHandler(req("POST", "/records", { envelope: envCase }, auth), env)).status, 400);
    }
  });
});

describe("review #5: no Bearer — x-did + x-session only", () => {
  it("rejects Authorization header auth and requires the x-did/x-session pair", async () => {
    const auth = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    const headers = {};
    headers["authorization"] = "Bearer " + auth.session;
    assert.equal((await fetchHandler(rawReq("POST", "/records", { envelope }, headers), env)).status, 401);
    assert.equal((await fetchHandler(rawReq("GET", "/records", undefined, { "x-session": auth.session }), env)).status, 401);
    assert.equal((await fetchHandler(rawReq("GET", "/records", undefined, { "x-did": auth.did }), env)).status, 401);
    const other = await makeSession();
    assert.equal((await fetchHandler(req("GET", "/records", undefined, { did: other.did, session: auth.session }), env)).status, 401);
    assert.equal((await fetchHandler(req("GET", "/records", undefined, auth), env)).status, 200);
  });
});

describe("review #6: D1 failure is 503, duplicate only on constraint violation", () => {
  // Auth tables work (session lives there), only sealed_records writes fail —
  // the single binding now serves both, so a blanket-failing stub could no
  // longer distinguish a record-store failure from an auth failure.
  function failingRecordsD1(message, baseDb) {
    const inner = baseDb ?? createFakeD1();
    return {
      prepare(sql) {
        const stmt = inner.prepare(sql);
        return { bind(...params) {
          const bound = stmt.bind(...params);
          if (sql.includes("INSERT INTO sealed_records")) {
            return {
              async run() { throw new Error(message); },
              async first() { throw new Error(message); },
              async all() { throw new Error(message); },
            };
          }
          return bound;
        } };
      },
      batch: (stmts) => inner.batch(stmts),
    };
  }
  it("maps a generic D1 error to 503 (not 409) and a constraint violation to 409", async () => {
    const db = createFakeD1();
    const auth = await makeSession(db);
    const envelope = await sealPayload(synthetic, PASS);
    const generic = await fetchHandler(req("POST", "/records", { envelope }, auth), { EIGYO_DB: failingRecordsD1("D1_ERROR: database is locked", db) });
    assert.equal(generic.status, 503);
    assert.deepEqual(await json(generic), { error: "store-unavailable" });
    const constraint = await fetchHandler(req("POST", "/records", { envelope }, auth), { EIGYO_DB: failingRecordsD1("UNIQUE constraint failed: sealed_records.id", db) });
    assert.equal(constraint.status, 409);
    // Reads against a fully-dead DB still map to 503 (session lookup fails).
    const dead = { prepare() { throw new Error("boom"); } };
    assert.equal((await fetchHandler(req("GET", "/records", undefined, auth), { EIGYO_DB: dead })).status, 503);
    assert.equal((await fetchHandler(req("GET", "/records/11111111-1111-4111-8111-111111111111", undefined, auth), { EIGYO_DB: dead })).status, 503);
  });
});

describe("review #7: malformed %-encoding returns 400, never throws", () => {
  it("GET /records/%E0%A4 and GET /ipfs/%E0%A4 answer 400", async () => {
    const auth = await makeSession();
    assert.equal((await fetchHandler(req("GET", "/records/%E0%A4", undefined, auth), env)).status, 400);
    let fetched = false;
    const spyFetch = async () => { fetched = true; return new Response("x"); };
    assert.equal((await fetchHandler(req("GET", "/ipfs/%E0%A4"), env, spyFetch)).status, 400);
    assert.equal(fetched, false);
  });
});

describe("Kougi K1/K2: pure-JS Ed25519 deleted; small-order/non-canonical rejected", () => {
  it("K1: src/auth.js contains no pure-JS secret-scalar code (scalarMult/modInv gone)", () => {
    const raw = readFileSync(new URL("../src/auth.js", import.meta.url), "utf8");
    // Header comments document the deleted code by name; check code only.
    const src = raw.split("\n").map((l) => l.replace(/\/\/.*$/, "")).join("\n");
    assert.equal(src.includes("function scalarMult"), false);
    assert.equal(src.includes("function modInv"), false);
    assert.equal(src.includes("function modPow"), false);
    assert.equal(src.includes("scalarMult("), false);
    assert.ok(src.includes('"Ed25519"'));
    assert.ok(src.includes("subtle.verify"));
    assert.ok(src.includes("subtle.sign"));
  });
  it("K2: identity (small-order) forgery that raw WebCrypto accepts is rejected", async () => {
    const identity = new Uint8Array(32);
    identity[0] = 1;
    assert.equal(isSmallOrderEncoding(identity), true);
    const basepoint = Buffer.from("5866666666666666666666666666666666666666666666666666666666666666", "hex");
    const s1 = new Uint8Array(32);
    s1[0] = 1;
    const forged = new Uint8Array(Buffer.concat([basepoint, Buffer.from(s1)]));
    assert.equal(await ed25519Verify(identity, new TextEncoder().encode("anything"), forged), false);
    const smallHex = [
      "0000000000000000000000000000000000000000000000000000000000000000",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
      "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
      "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
      "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ];
    for (const h of smallHex) {
      const key = new Uint8Array(Buffer.from(h, "hex"));
      assert.equal(isSmallOrderEncoding(key), true, h);
      assert.equal(await ed25519Verify(key, new TextEncoder().encode("x"), forged), false, h);
    }
  });
  it("K2: non-canonical encodings (y+p public key, S+L signature) are rejected", async () => {
    const fromHex = (h) => new Uint8Array(Buffer.from(h, "hex"));
    const pub = fromHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    const sig = fromHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    const empty = new Uint8Array(0);
    assert.equal(await ed25519Verify(pub, empty, sig), true);
    const p = (1n << 255n) - 19n;
    const sign = (pub[31] >> 7) & 1;
    const yBytes = Uint8Array.from(pub);
    yBytes[31] &= 0x7f;
    let y = 0n;
    for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(yBytes[i]);
    const nonCanon = new Uint8Array(32);
    let v = y + p;
    for (let i = 0; i < 32; i++) { nonCanon[i] = Number(v & 0xffn); v >>= 8n; }
    if (sign) nonCanon[31] |= 0x80;
    assert.equal(await ed25519Verify(nonCanon, empty, sig), false);
    const L = (1n << 252n) + 27742317777372353535851937790883648493n;
    let s = 0n;
    const sBytes = sig.slice(32);
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sBytes[i]);
    const s2Bytes = new Uint8Array(32);
    let w = s + L;
    for (let i = 0; i < 32; i++) { s2Bytes[i] = Number(w & 0xffn); w >>= 8n; }
    const sigNonCanon = new Uint8Array(Buffer.concat([Buffer.from(sig.slice(0, 32)), Buffer.from(s2Bytes)]));
    assert.equal(await ed25519Verify(pub, empty, sigNonCanon), false);
  });
});

describe("Kougi K3: build script syntax-checks src/auth.js", () => {
  it("package.json build includes node --check src/auth.js", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
    assert.ok(pkg.scripts.build.includes("node --check src/auth.js"), pkg.scripts.build);
  });
});
