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
  pubkeyToDid,
} from "../src/auth.js";
import { openPayload, sealPayload } from "../src/seal.js";

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
const req = (method, path, body, token) =>
  new Request(base + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

async function json(res) {
  return res.json();
}

// Full client flow: generate keypair -> challenge -> sign -> verify -> session.
async function makeSession() {
  const { seed, publicKey } = await ed25519GenerateKeypair();
  const did = pubkeyToDid(publicKey);
  const challengeRes = await fetchHandler(req("POST", "/auth/challenge", { did }), {});
  assert.equal(challengeRes.status, 201);
  const challenge = await json(challengeRes);
  const message = canonicalAuthMessage({
    nonce: challenge.nonce,
    purpose: challenge.purpose,
    timestamp: challenge.timestamp,
  });
  const signature = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(message))).toString("base64");
  const verifyRes = await fetchHandler(req("POST", "/auth/verify", { did, nonce: challenge.nonce, signature }), {});
  assert.equal(verifyRes.status, 200);
  const verified = await json(verifyRes);
  return { seed, did, token: verified.token };
}

describe("ed25519 pure-JS vs RFC 8032 vectors + native Node Ed25519", () => {
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
    const auth = createAuthService({ now: () => t });
    assert.deepEqual(auth.issueChallenge("did:key:z0").ok, false);
    const { seed, publicKey } = await ed25519GenerateKeypair();
    const did = pubkeyToDid(publicKey);
    const c = auth.issueChallenge(did);
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
    const c2 = auth.issueChallenge(did);
    const msg2 = canonicalAuthMessage({ nonce: c2.nonce, purpose: c2.purpose, timestamp: c2.timestamp });
    const sig2 = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(msg2))).toString("base64");
    t += 5 * 60 * 1000 + 1;
    assert.deepEqual(await auth.verifyResponse({ did, nonce: c2.nonce, signature: sig2 }), {
      ok: false,
      error: "auth-failed",
    });
    // valid -> session -> expired session
    t = 1_000_000;
    const c3 = auth.issueChallenge(did);
    const msg3 = canonicalAuthMessage({ nonce: c3.nonce, purpose: c3.purpose, timestamp: c3.timestamp });
    const sig3 = Buffer.from(await ed25519Sign(seed, new TextEncoder().encode(msg3))).toString("base64");
    const verified = await auth.verifyResponse({ did, nonce: c3.nonce, signature: sig3 });
    assert.equal(verified.ok, true);
    assert.equal(auth.getSession(verified.token), did);
    t += 30 * 60 * 1000 + 1;
    assert.equal(auth.getSession(verified.token), null);
  });
});

describe("worker http surface", () => {
  it("serves health with yataverse storage flag", async () => {
    const res = await fetchHandler(req("GET", "/health"), {});
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.deepEqual(body, { ok: true, service: "app-itonami-eigyo", storage: "yataverse", r2: false });
  });

  it("auth: challenge/verify over HTTP; bad did 400; bad sig 401; no session = 401", async () => {
    const badDid = await fetchHandler(req("POST", "/auth/challenge", { did: "did:key:z0" }), {});
    assert.equal(badDid.status, 400);

    const { seed, publicKey } = await ed25519GenerateKeypair();
    const did = pubkeyToDid(publicKey);
    const ch = await json(await fetchHandler(req("POST", "/auth/challenge", { did }), {}));
    const wrongSig = Buffer.from(
      await ed25519Sign(seed, new TextEncoder().encode("nonce||purpose||timestamp")),
    ).toString("base64");
    const wrong = await fetchHandler(req("POST", "/auth/verify", { did, nonce: ch.nonce, signature: wrongSig }), {});
    assert.equal(wrong.status, 401);
    assert.deepEqual(await json(wrong), { error: "auth-failed" });

    const meh = await fetchHandler(req("GET", "/records"), {});
    assert.equal(meh.status, 401);
    assert.deepEqual(await json(meh), { error: "unauthorized" });
  });

  it("sealed records: end-to-end seal -> store -> fetch -> open (negative-control a)", async () => {
    const { did, token } = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    const created = await fetchHandler(
      req("POST", "/records", { id: "record_alpha", envelope, cid: "bafy-synthetic-cid", seq: 1 }, token),
      {},
    );
    assert.equal(created.status, 201);
    const meta = await json(created);
    assert.equal(meta.owner_id, did);
    assert.equal(meta.cid, "bafy-synthetic-cid");
    assert.equal(meta.envelope, undefined); // metadata only
    assert.equal(JSON.stringify(meta).includes("Synthetic"), false);

    const fetched = await fetchHandler(req("GET", "/records/record_alpha", undefined, token), {});
    assert.equal(fetched.status, 200);
    const record = await json(fetched);
    assert.deepEqual(await openPayload(record.envelope, PASS), synthetic);

    const listed = await fetchHandler(req("GET", "/records", undefined, token), {});
    const items = (await json(listed)).items;
    assert.ok(items.some((r) => r.id === "record_alpha"));
    assert.ok(items.every((r) => r.envelope === undefined)); // list never leaks envelopes
  });

  it("sealed records: owner scoping, bad envelope/cid/seq, duplicates", async () => {
    const a = await makeSession();
    const b = await makeSession();
    const envelope = await sealPayload(synthetic, PASS);
    await fetchHandler(req("POST", "/records", { id: "record_bravo", envelope }, a.token), {});
    // other owner -> 404 (existence not leaked), missing -> 404 never 500
    assert.equal((await fetchHandler(req("GET", "/records/record_bravo", undefined, b.token), {})).status, 404);
    const missing = await fetchHandler(req("GET", "/records/nope", undefined, a.token), {});
    assert.equal(missing.status, 404);
    assert.notEqual(missing.status, 500);
    // bad envelope / bad cid / bad seq / duplicate
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope: { v: 2 } }, a.token), {})).status,
      400,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope, cid: "a/b" }, a.token), {})).status,
      400,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope, seq: -1 }, a.token), {})).status,
      400,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { id: "record_bravo", envelope }, a.token), {})).status,
      409,
    );
    assert.equal(
      (await fetchHandler(req("POST", "/records", { envelope, cid: "bad cid" }, a.token), {})).status,
      400,
    );
  });

  it("plaintext routes are removed (server-side search/report gone by design)", async () => {
    const { token } = await makeSession();
    assert.equal((await fetchHandler(req("GET", "/opportunities", undefined, token), {})).status, 404);
    assert.equal((await fetchHandler(req("POST", "/opportunities", { name: "X" }, token), {})).status, 404);
    assert.equal((await fetchHandler(req("GET", "/report", undefined, token), {})).status, 404);
    assert.equal((await fetchHandler(req("GET", "/accounts", undefined, token), {})).status, 404);
  });
});

describe("EIGYO_DB (D1) wiring via fake D1", () => {
  function fakeD1() {
    const rows = new Map();
    return {
      _rows: rows,
      prepare(sql) {
        return {
          bind(...params) {
            return {
              async run() {
                if (sql.includes("INSERT INTO sealed_records")) {
                  const [id, owner_id, cid, envelope, seq, created_at, updated_at] = params;
                  if (rows.has(id)) throw new Error("UNIQUE constraint failed: sealed_records.id");
                  rows.set(id, { id, owner_id, cid, envelope, seq, created_at, updated_at });
                  return { success: true };
                }
                throw new Error("unsupported sql");
              },
              async first() {
                if (sql.includes("FROM sealed_records WHERE id = ?")) return rows.get(params[0]) ?? null;
                throw new Error("unsupported sql");
              },
              async all() {
                if (sql.includes("WHERE owner_id = ?")) {
                  return {
                    success: true,
                    results: [...rows.values()]
                      .filter((r) => r.owner_id === params[0])
                      .sort((x, y) => x.seq - y.seq || String(x.created_at).localeCompare(String(y.created_at))),
                  };
                }
                throw new Error("unsupported sql");
              },
            };
          },
        };
      },
    };
  }

  it("stores/fetches sealed_records via env.EIGYO_DB (ciphertext only)", async () => {
    const db = fakeD1();
    const env = { EIGYO_DB: db };
    const { did, token } = await makeSession();
    // auth calls use the shared in-memory auth service regardless of env
    const envelope = await sealPayload(synthetic, PASS);
    const created = await fetchHandler(req("POST", "/records", { id: "record_d1", envelope }, token), env);
    assert.equal(created.status, 201);
    const row = db._rows.get("record_d1");
    assert.ok(row);
    assert.equal(row.owner_id, did);
    const storedText = JSON.stringify(row);
    assert.equal(storedText.includes(synthetic.name), false);
    assert.equal(storedText.includes("Synthetic Co 000"), false);

    const fetched = await fetchHandler(req("GET", "/records/record_d1", undefined, token), env);
    assert.equal(fetched.status, 200);
    assert.deepEqual(await openPayload((await json(fetched)).envelope, PASS), synthetic);
    const listed = await json(await fetchHandler(req("GET", "/records", undefined, token), env));
    assert.ok(listed.items.some((r) => r.id === "record_d1"));
    assert.ok(listed.items.every((r) => r.envelope === undefined));
  });
});

describe("yataverse proxy (contracts preserved)", () => {
  it("streams upstream body with content-type; missing/error -> 404 never 500", async () => {
    const okFetch = async () =>
      new Response("blob-bytes", { status: 200, headers: { "content-type": "image/png" } });
    const res = await fetchHandler(req("GET", "/ipfs/bafy-cid"), {}, okFetch);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get("content-type"), "image/png");
    assert.equal(res.headers.get("cache-control"), "public, max-age=300");
    assert.equal(await res.text(), "blob-bytes");

    const missingFetch = async () => new Response("nope", { status: 404 });
    const missing = await fetchHandler(req("GET", "/ipfs/bafy-cid"), {}, missingFetch);
    assert.equal(missing.status, 404);
    assert.notEqual(missing.status, 500);

    const throwFetch = async () => {
      throw new Error("network down");
    };
    const unreachable = await fetchHandler(req("GET", "/ipfs/bafy-cid"), {}, throwFetch);
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
      const res = await fetchHandler(req("GET", `/ipfs/${bad}`), {}, spyFetch);
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
