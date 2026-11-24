import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fetchHandler } from "../src/worker.js";

const base = "http://localhost";
const req = (method, path, body) =>
  new Request(base + path, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

async function json(res) {
  return res.json();
}

describe("worker http surface", () => {
  it("serves health with yataverse storage flag", async () => {
    const res = await fetchHandler(req("GET", "/health"), {});
    assert.equal(res.status, 200);
    const body = await json(res);
    assert.equal(body.ok, true);
    assert.equal(body.service, "app-itonami-eigyo");
    assert.equal(body.storage, "yataverse");
    assert.equal(body.r2, false);
  });

  it("creates accounts and opportunities, transitions, and 404s unknown ids", async () => {
    const acct = await fetchHandler(req("POST", "/accounts", { name: "Wing-Account" }), {});
    assert.equal(acct.status, 201);
    const account = await json(acct);
    const bad = await fetchHandler(req("POST", "/opportunities", { name: "X", accountId: "missing" }), {});
    assert.equal(bad.status, 400);
    const created = await fetchHandler(
      req("POST", "/opportunities", { name: "Wing deal", amount: 100, probability: 40, accountId: account.id, ownerId: "u-9" }),
      {},
    );
    assert.equal(created.status, 201);
    const opp = await json(created);
    assert.equal(opp.stage, "prospecting");
    const moved = await fetchHandler(req("POST", `/opportunities/${opp.id}/transition`, { to: "proposal" }), {});
    assert.equal(moved.status, 200);
    assert.equal((await json(moved)).stage, "proposal");
    const illegal = await fetchHandler(req("POST", `/opportunities/${opp.id}/transition`, { to: "voodoo" }), {});
    assert.equal(illegal.status, 400);
    const missing = await fetchHandler(req("POST", "/opportunities/nope/transition", { to: "won" }), {});
    assert.equal(missing.status, 404);
  });

  it("scopes /opportunities and /report by role", async () => {
    const res = await fetchHandler(req("GET", "/opportunities?role=owner"), {});
    const ownerItems = (await json(res)).items;
    const memberRes = await fetchHandler(req("GET", "/opportunities?role=member&userId=u-9"), {});
    const memberItems = (await json(memberRes)).items;
    assert.ok(ownerItems.length >= 1);
    assert.ok(memberItems.length >= 1 && memberItems.length <= ownerItems.length);
    assert.ok(memberItems.every((o) => o.ownerId === "u-9"));
    const reportRes = await fetchHandler(req("GET", "/report?role=member&userId=u-9"), {});
    assert.equal(reportRes.status, 200);
    const report = await json(reportRes);
    assert.deepEqual(
      report.byStage.map((r) => r.stage),
      ["prospecting", "proposal", "negotiation", "won", "lost"],
    );
    assert.equal(report.scope.role, "member");
    const quarterRes = await fetchHandler(req("GET", "/report?role=owner&quarter=1900-Q1"), {});
    const quarterReport = await json(quarterRes);
    assert.equal(quarterReport.quarterly.length, 0);
  });
});

describe("yataverse proxy", () => {
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
    // Note: ".." / "%2E%2E" are dot-segments normalized by the URL parser
    // before the handler runs (path becomes "/" and 404s as unknown route),
    // so the ".." guard is exercised via "..x" (not a dot segment).
    for (const bad of ["", "..x", "a%2Fb", "%5C", "a%20b", "b%00ad"]) {
      const res = await fetchHandler(req("GET", `/ipfs/${bad}`), {}, spyFetch);
      assert.equal(res.status, 400, `expected 400 for CID ${bad}`);
    }
    assert.equal(fetched, false);
  });
});

describe("R2 non-dependence", () => {
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
    for (const file of ["src/sfa.js", "src/worker.js", "src/seal.js"]) {
      const code = stripComments(readFileSync(new URL(`../${file}`, import.meta.url), "utf8"));
      assert.equal(code.includes("R2."), false, `${file} must not reference R2.`);
      assert.equal(code.includes("r2_buckets"), false, `${file} must not reference r2_buckets`);
    }
  });
});
