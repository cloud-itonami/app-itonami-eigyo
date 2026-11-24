import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  KDF_ITERATIONS,
  KDF_NAME,
  SEAL_ALG,
  importKey,
  migrateToV2,
  newKey,
  openPayload,
  resealPayload,
  rewrapPayload,
  sealPayload,
  sealPayloadV1,
} from "../src/seal.js";

// Synthetic payload only — no real opportunity/customer data in this repo.
// Passphrases below are synthetic test values, never real credentials.
const synthetic = {
  name: "Synthetic Deal Alpha",
  amount: 12345,
  probability: 60,
  stage: "negotiation",
  account: "Synthetic Co 000",
  owner: "synthetic-user-000",
  canary: "Synthetic-Canary-7f3a9c2e-vault",
};
const PASS = "synthetic-test-passphrase-000";
const PASS2 = "synthetic-test-passphrase-111";

// Negative-control (a): round-trip seal -> store/fetch-equivalent -> open matches.
describe("seal round-trip (encrypt -> store -> fetch -> decrypt)", () => {
  it("v2 envelope recovers the payload exactly", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    assert.equal(envelope.v, 2);
    assert.equal(envelope.alg, SEAL_ALG);
    assert.equal(envelope.kdf.name, KDF_NAME);
    assert.equal(envelope.kdf.iterations, KDF_ITERATIONS);
    assert.equal(KDF_ITERATIONS, 600000);
    assert.equal(envelope.wrappedKey.alg, SEAL_ALG);
    const stored = JSON.stringify(envelope); // what D1 stores as `envelope` TEXT
    const fetched = JSON.parse(stored);      // what GET /records/:id returns
    assert.deepEqual(await openPayload(fetched, PASS), synthetic);
  });

  it("two seals of the same payload differ (random salt/IV/DEK)", async () => {
    const a = await sealPayload(synthetic, PASS);
    const b = await sealPayload(synthetic, PASS);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.data, b.data);
    assert.notEqual(a.kdf.salt, b.kdf.salt);
    assert.notEqual(a.wrappedKey.data, b.wrappedKey.data);
    assert.deepEqual(await openPayload(a, PASS), synthetic);
    assert.deepEqual(await openPayload(b, PASS), synthetic);
  });
});

// Negative-control (b)+(c): wrong passphrase and 1-byte tamper both fail
// open with no plaintext returned.
describe("negative controls: wrong passphrase / tamper", () => {
  it("rejects the wrong passphrase (no plaintext restored)", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    await assert.rejects(openPayload(envelope, PASS2));
    await assert.rejects(openPayload(envelope, "synthetic-test-passphrase-wrong"));
  });

  it("rejects 1-byte tampering (AES-GCM auth failure) + bad shapes", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    const raw = Buffer.from(envelope.data, "base64");
    raw[0] ^= 0xff; // flip exactly one byte
    await assert.rejects(openPayload({ ...envelope, data: raw.toString("base64") }, PASS));
    const wrapped = Buffer.from(envelope.wrappedKey.data, "base64");
    wrapped[0] ^= 0x01;
    await assert.rejects(openPayload({ ...envelope, wrappedKey: { ...envelope.wrappedKey, data: wrapped.toString("base64") } }, PASS));
    await assert.rejects(openPayload({ ...envelope, v: 3 }, PASS));
    await assert.rejects(openPayload({ ...envelope, kdf: undefined }, PASS));
    await assert.rejects(openPayload(null, PASS));
  });
});

// Negative-control (d): ciphertext contains no plaintext substring.
describe("negative control: no plaintext in ciphertext", () => {
  it("stored envelope has 0 hits for payload substrings", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    const stored = JSON.stringify(envelope);
    for (const token of [synthetic.name, synthetic.account, synthetic.canary, synthetic.owner]) {
      assert.equal(stored.includes(token), false, `plaintext leak: ${token}`);
    }
    // also decode fields: the raw bytes must not contain the canary either
    const decoded = Buffer.concat([
      Buffer.from(envelope.data, "base64"),
      Buffer.from(envelope.wrappedKey.data, "base64"),
      Buffer.from(envelope.kdf.salt, "base64"),
    ]).toString("latin1");
    assert.equal(decoded.includes("Synthetic"), false);
  });
});

// Rotation = re-wrap DEK only; DEK rotation = re-seal.
describe("rotation (re-wrap vs re-seal)", () => {
  it("rewrap changes wrappedKey/kdf but leaves data untouched; new passphrase opens", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    const rewrapped = await rewrapPayload(envelope, PASS, PASS2);
    assert.equal(rewrapped.iv, envelope.iv);
    assert.equal(rewrapped.data, envelope.data);
    assert.notEqual(rewrapped.wrappedKey.data, envelope.wrappedKey.data);
    assert.notEqual(rewrapped.kdf.salt, envelope.kdf.salt);
    assert.deepEqual(await openPayload(rewrapped, PASS2), synthetic);
    await assert.rejects(openPayload(rewrapped, PASS));
    await assert.rejects(rewrapPayload(envelope, PASS2, PASS));
  });

  it("reseal (DEK rotation) changes ciphertext; new passphrase opens", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    const resealed = await resealPayload(envelope, PASS, PASS2);
    assert.notEqual(resealed.data, envelope.data);
    assert.deepEqual(await openPayload(resealed, PASS2), synthetic);
    await assert.rejects(openPayload(resealed, PASS));
  });
});

// v1 -> v2 migration: open v1, re-seal as v2, v1 stays openable.
describe("v1 -> v2 migration", () => {
  it("migrates a v1 envelope to v2; v1 remains openable", async () => {
    const key = await newKey();
    const v1 = await sealPayloadV1(synthetic, key);
    assert.equal(v1.v, 1);
    assert.deepEqual(await openPayload(v1, key), synthetic); // v1 open kept
    const v2 = await migrateToV2(v1, key, PASS);
    assert.equal(v2.v, 2);
    assert.deepEqual(await openPayload(v2, PASS), synthetic);
    await assert.rejects(migrateToV2(v2, key, PASS)); // not a v1 envelope
  });

  it("v1 wrong key still fails; importKey rejects non-32-byte keys", async () => {
    const key = await newKey();
    const v1 = await sealPayloadV1(synthetic, key);
    await assert.rejects(openPayload(v1, await newKey()));
    await assert.rejects(importKey(new Uint8Array(16)));
    const imported = await importKey(new Uint8Array(32).map((_, i) => i));
    assert.deepEqual(await openPayload(await sealPayloadV1(synthetic, imported), imported), synthetic);
  });
});

// Review #3 (client side): KDF parameters are FIXED, not taken from the
// envelope. openPayload/rewrapPayload must reject non-600k iterations or
// non-16B salts BEFORE any PBKDF2 work (no 30M-iteration DoS).
describe("review #3: KDF fixation in openPayload/rewrapPayload", () => {
  it("openPayload rejects iterations 1 / 30000000 / bad salt with a kdf error, fast", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    const bad = [
      { ...envelope, kdf: { ...envelope.kdf, iterations: 1 } },
      { ...envelope, kdf: { ...envelope.kdf, iterations: 30000000 } },
      { ...envelope, kdf: { ...envelope.kdf, iterations: 599999 } },
      { ...envelope, kdf: { ...envelope.kdf, salt: "" } },
      { ...envelope, kdf: { ...envelope.kdf, salt: Buffer.alloc(8, 7).toString("base64") } },
    ];
    for (const env of bad) {
      const t0 = Date.now();
      await assert.rejects(openPayload(env, PASS), /kdf/);
      assert.ok(Date.now() - t0 < 1000, "must reject before PBKDF2 (no DoS window)");
    }
  });
  it("rewrapPayload rejects a tampered KDF the same way", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    await assert.rejects(
      rewrapPayload({ ...envelope, kdf: { ...envelope.kdf, iterations: 1 } }, PASS, PASS2),
      /kdf/,
    );
    await assert.rejects(
      rewrapPayload({ ...envelope, kdf: { ...envelope.kdf, salt: "" } }, PASS, PASS2),
      /kdf/,
    );
  });
  it("openPayload rejects wrong iv/wrapped lengths", async () => {
    const envelope = await sealPayload(synthetic, PASS);
    const b64 = (n) => Buffer.alloc(n, 7).toString("base64");
    await assert.rejects(openPayload({ ...envelope, iv: b64(8) }, PASS), /iv/);
    await assert.rejects(openPayload({ ...envelope, data: b64(4) }, PASS), /data/);
    await assert.rejects(
      openPayload({ ...envelope, wrappedKey: { ...envelope.wrappedKey, data: b64(32) } }, PASS),
      /wrappedKey/,
    );
  });
});
