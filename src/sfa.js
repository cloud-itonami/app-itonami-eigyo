// app-itonami-eigyo — SFA skeleton domain (plain JS, zero deps).
// Adds only what the existing kotoba implementation does not have:
//   - probability (確度) per opportunity
//   - account (案件/会社) as a linked entity (kotoba lead carries `company`
//     as a bare string; this layer lets an opportunity link to an account)
//   - reports (by-stage counts/sums, quarterly aggregation)
//   - role-scoped visibility (owner = all, member = own only)
// The opportunity stage machine mirrors the existing kotoba convention
// (kotoba/src/types.ts DealStage, kotoba/src/deal.ts advanceDeal):
// stages are prospecting/proposal/negotiation/won/lost; won/lost are
// terminal (immutable); an unknown stage name is rejected. The kotoba
// TypeScript layer stays authoritative on AT PDS records; this module is
// the plain-JS Worker surface (no build step, runnable via `node --test`).
// In-memory store is the skeleton stand-in; schema.sql mirrors this shape
// for D1 (free tier only). No R2, no network: content read/write goes
// through the yataverse.com protocol only (GET https://yataverse.com/ipfs/<cid>).

export const OPPORTUNITY_STAGES = ["prospecting", "proposal", "negotiation", "won", "lost"];
export const TERMINAL_STAGES = ["won", "lost"];

export function isValidStage(stage) {
  return OPPORTUNITY_STAGES.includes(stage);
}

// Mirrors kotoba advanceDeal: any non-terminal deal may move to any valid
// stage; a terminal (won/lost) deal can never be re-staged.
export function validateTransition(from, to) {
  if (!isValidStage(to)) return { ok: false, error: "unknown-stage", to };
  if (TERMINAL_STAGES.includes(from)) return { ok: false, error: "terminal", from, to };
  return { ok: true };
}

function newId(prefix) {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

export function createStore() {
  return { accounts: new Map(), opportunities: new Map() };
}

export function createAccount(store, input) {
  const name = String(input?.name ?? "").trim();
  if (!name) return { ok: false, error: "name-required" };
  const account = { id: newId("account"), name, createdAt: new Date().toISOString() };
  store.accounts.set(account.id, account);
  return { ok: true, account };
}

export function createOpportunity(store, input) {
  const name = String(input?.name ?? "").trim();
  if (!name) return { ok: false, error: "name-required" };
  const amount = input?.amount === undefined ? 0 : Number(input.amount);
  if (!Number.isFinite(amount) || amount < 0)
    return { ok: false, error: "amount-invalid" };
  const probability = input?.probability === undefined ? 0 : Number(input.probability);
  if (!Number.isFinite(probability) || probability < 0 || probability > 100)
    return { ok: false, error: "probability-invalid" };
  const accountId = input?.accountId ? String(input.accountId) : null;
  if (!accountId || !store.accounts.has(accountId))
    return { ok: false, error: "account-not-found" };
  const opportunity = {
    id: newId("opportunity"),
    name,
    amount,
    probability,
    stage: "prospecting",
    accountId,
    ownerId: String(input?.ownerId ?? ""),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  store.opportunities.set(opportunity.id, opportunity);
  return { ok: true, opportunity };
}

export function transitionOpportunity(store, id, to) {
  const opportunity = store.opportunities.get(id);
  if (!opportunity) return { ok: false, error: "not-found", id };
  const check = validateTransition(opportunity.stage, String(to ?? ""));
  if (!check.ok) return check;
  opportunity.stage = String(to);
  opportunity.updatedAt = new Date().toISOString();
  store.opportunities.set(opportunity.id, opportunity);
  return { ok: true, opportunity };
}

// Role visibility: "owner" sees every opportunity; any other role is
// treated as "member" and sees only rows whose ownerId === userId. A
// member query without a userId sees nothing.
export function scopeOpportunities(items, { role = "member", userId = "" } = {}) {
  if (role === "owner") return [...items];
  return items.filter((o) => o.ownerId === userId);
}

function quarterOf(iso) {
  const d = new Date(iso);
  return `${d.getUTCFullYear()}-Q${Math.floor(d.getUTCMonth() / 3) + 1}`;
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

// Report over already-scoped opportunities: per-stage count + amount sum
// (+ probability-weighted sum) and per-quarter totals (quarters are UTC,
// taken from createdAt). Deterministic order: stages in OPPORTUNITY_STAGES
// order, quarters ascending.
export function reportOpportunities(items) {
  const byStage = OPPORTUNITY_STAGES.map((stage) => {
    const rows = items.filter((o) => o.stage === stage);
    const amountTotal = rows.reduce((sum, o) => sum + o.amount, 0);
    const weightedTotal = rows.reduce(
      (sum, o) => sum + (o.amount * o.probability) / 100,
      0,
    );
    return { stage, count: rows.length, amountTotal: round2(amountTotal), weightedTotal: round2(weightedTotal) };
  });
  const quarters = new Map();
  for (const o of items) {
    const quarter = quarterOf(o.createdAt);
    const row = quarters.get(quarter) ?? { quarter, count: 0, amountTotal: 0, weightedTotal: 0 };
    row.count += 1;
    row.amountTotal += o.amount;
    row.weightedTotal += (o.amount * o.probability) / 100;
    quarters.set(quarter, row);
  }
  const quarterly = [...quarters.values()]
    .sort((a, b) => (a.quarter < b.quarter ? -1 : 1))
    .map((r) => ({ ...r, amountTotal: round2(r.amountTotal), weightedTotal: round2(r.weightedTotal) }));
  return { byStage, quarterly };
}

function matchesQuery(obj, q) {
  if (!q) return true;
  const hay = Object.values(obj).filter((v) => typeof v === "string" || typeof v === "number").join(" ").toLowerCase();
  return hay.includes(q.toLowerCase());
}

export function listAccounts(store, q) {
  return [...store.accounts.values()].filter((a) => matchesQuery(a, q));
}

export function listOpportunities(store, { q, stage, role, userId } = {}) {
  const scoped = scopeOpportunities([...store.opportunities.values()], { role, userId });
  return scoped.filter((o) => matchesQuery(o, q) && (!stage || o.stage === stage));
}
