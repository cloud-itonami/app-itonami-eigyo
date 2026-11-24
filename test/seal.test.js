import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { importKey, newKey, openPayload, sealPayload } from "../src/seal.js";

// Synthetic payload only — no real opportunity/customer data in this repo.
const synthetic = {
  name: "Synthetic Deal Alpha",
  amount: 12345,
  probability: 60,
  stage: "negotiation",
  account: "Synthetic Co 000",
  owner: "synthetic-user-000",
};

describe("seal round-trip (encrypt -> put-equivalent -> fetch -> decrypt)", () => {
  it("recovers the payload exactly", async () => {
    const key = await newKey();
    const envelope = await sealPayload(synthetic, key);
    assert.equal(envelope.v, 1);
    assert.equal(envelope.alg, "AES-256-GCM");
    const stored = JSON.stringify(envelope); // what would be `yataverse put`
    const fetched = JSON.parse(stored);      // what `GET /ipfs/<cid>` returns
    assert.deepEqual(await openPayload(fetched, key), synthetic);
  });

  it("ciphertext does not leak plaintext (CID knowledge alone cannot read it)", async () => {
    const key = await newKey();
    const envelope = await sealPayload(synthetic, key);
    const stored = JSON.stringify(envelope);
    assert.equal(stored.includes(synthetic.name), false);
    assert.equal(stored.includes(synthetic.account), false);
    assert.equal(stored.includes("Synthetic"), false);
  });

  it("two seals of the same payload differ (random IV)", async () => {
    const key = await newKey();
    const a = await sealPayload(synthetic, key);
    const b = await sealPayload(synthetic, key);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.data, b.data);
    assert.deepEqual(await openPayload(a, key), synthetic);
    assert.deepEqual(await openPayload(b, key), synthetic);
  });

  it("rejects the wrong key (no plaintext restored)", async () => {
    const key = await newKey();
    const envelope = await sealPayload(synthetic, key);
    const wrongKey = await newKey();
    await assert.rejects(openPayload(envelope, wrongKey));
  });

  it("rejects tampered ciphertext and swapped envelopes", async () => {
    const key = await newKey();
    const envelope = await sealPayload(synthetic, key);
    // flip one byte deterministically
    const raw = Buffer.from(envelope.data, "base64");
    raw[0] ^= 0xff;
    const flipped = { ...envelope, data: raw.toString("base64") };
    await assert.rejects(openPayload(flipped, key));
    await assert.rejects(openPayload({ ...envelope, v: 2 }, key));
    await assert.rejects(openPayload(null, key));
  });

  it("importKey rejects non-32-byte keys; importKey path round-trips", async () => {
    await assert.rejects(importKey(new Uint8Array(16)));
    const key = await importKey(new Uint8Array(32).map((_, i) => i));
    const envelope = await sealPayload(synthetic, key);
    assert.deepEqual(await openPayload(envelope, key), synthetic);
  });
});
