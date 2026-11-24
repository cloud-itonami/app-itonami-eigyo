// app-itonami-eigyo Worker — plain JS, zero dependencies.
// R2 NON-DEPENDENCE (owner policy 2026-11-23): no R2 binding, no R2 API.
// Content read:  GET https://yataverse.com/ipfs/<cid> (verified against CID)
// Content write: yataverse put (out of scope for this skeleton — no write route)
// SFA state: in-memory store (skeleton). schema.sql is the D1 mirror for
// the free-tier D1 binding in wrangler.jsonc; wiring D1 is a later step.
// Missing objects answer 404, never 500 (cf. no-r2-yataverse-only.md).

import {
  createAccount,
  createOpportunity,
  createStore,
  listAccounts,
  listOpportunities,
  reportOpportunities,
  transitionOpportunity,
} from "./sfa.js";

const YATAVERSE = "https://yataverse.com";
const store = createStore();

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

export async function fetchHandler(request, env, fetchImpl = fetch) {
  const url = new URL(request.url);
  const path = url.pathname;
  const q = url.searchParams.get("q") || "";
  const role = url.searchParams.get("role") || "member";
  const userId = url.searchParams.get("userId") || "";

  if (request.method === "GET" && path === "/health") {
    return json({ ok: true, service: "app-itonami-eigyo", storage: "yataverse", r2: false });
  }

  if (request.method === "GET" && path.startsWith("/ipfs/")) {
    return handleIpfs(decodeURIComponent(path.slice("/ipfs/".length)), fetchImpl);
  }

  if (request.method === "POST" && path === "/accounts") {
    const r = createAccount(store, await request.json().catch(() => null));
    return r.ok ? json(r.account, 201) : json({ error: r.error }, 400);
  }
  if (request.method === "GET" && path === "/accounts") {
    return json({ items: listAccounts(store, q) });
  }

  if (request.method === "POST" && path === "/opportunities") {
    const r = createOpportunity(store, await request.json().catch(() => null));
    return r.ok ? json(r.opportunity, 201) : json({ error: r.error }, 400);
  }
  if (request.method === "GET" && path === "/opportunities") {
    const stage = url.searchParams.get("stage") || "";
    return json({ items: listOpportunities(store, { q, stage, role, userId }) });
  }

  if (request.method === "GET" && path === "/report") {
    const quarter = url.searchParams.get("quarter") || "";
    const scoped = listOpportunities(store, { role, userId });
    const report = reportOpportunities(scoped);
    if (quarter) report.quarterly = report.quarterly.filter((r) => r.quarter === quarter);
    return json({ ...report, scope: { role, userId } });
  }

  const transitionMatch = path.match(/^\/opportunities\/([^/]+)\/transition$/);
  if (request.method === "POST" && transitionMatch) {
    const body = await request.json().catch(() => null);
    const r = transitionOpportunity(store, decodeURIComponent(transitionMatch[1]), body?.to);
    if (!r.ok) return json({ error: r.error, ...r }, r.error === "not-found" ? 404 : 400);
    return json(r.opportunity);
  }

  return json({ error: "not-found", path }, 404);
}

export default { fetch: fetchHandler };
