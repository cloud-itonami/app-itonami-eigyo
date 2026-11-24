import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createAccount,
  createOpportunity,
  createStore,
  listOpportunities,
  reportOpportunities,
  scopeOpportunities,
  transitionOpportunity,
  validateTransition,
} from "../src/sfa.js";

function seeded() {
  const store = createStore();
  const { account } = createAccount(store, { name: "Acme KK" });
  // createdAt is pinned per-opportunity so quarterly grouping is deterministic
  const mk = (name, amount, probability, ownerId, createdAt) => {
    const r = createOpportunity(store, { name, amount, probability, accountId: account.id, ownerId });
    assert.equal(r.ok, true);
    r.opportunity.createdAt = createdAt;
    return r.opportunity;
  };
  return { store, account, mk };
}

describe("opportunity stage transition (mirrors kotoba advanceDeal)", () => {
  it("walks prospecting -> proposal -> negotiation -> won", () => {
    const { store, mk } = seeded();
    const opp = mk("Acme annual license", 240000, 60, "u-1", "2026-11-01T00:00:00Z");
    assert.equal(opp.stage, "prospecting");
    for (const to of ["proposal", "negotiation", "won"]) {
      const r = transitionOpportunity(store, opp.id, to);
      assert.equal(r.ok, true, `expected ${to} ok`);
      assert.equal(r.opportunity.stage, to);
    }
    // terminal: won is immutable
    assert.equal(transitionOpportunity(store, opp.id, "lost").ok, false);
    assert.equal(validateTransition("won", "prospecting").ok, false);
  });

  it("rejects unknown stages, unknown ids, and lost-terminal re-stage", () => {
    const { store, mk } = seeded();
    const opp = mk("Globex pilot", 100, 30, "u-1", "2026-11-02T00:00:00Z");
    assert.deepEqual(transitionOpportunity(store, opp.id, "voodoo").error, "unknown-stage");
    assert.deepEqual(transitionOpportunity(store, "nope", "won").error, "not-found");
    const lost = transitionOpportunity(store, opp.id, "lost");
    assert.equal(lost.ok, true);
    assert.equal(transitionOpportunity(store, opp.id, "proposal").ok, false);
    assert.equal(validateTransition("lost", "won").ok, false);
  });

  it("validates createOpportunity input (amount, probability, account link)", () => {
    const { store, account } = seeded();
    assert.equal(createOpportunity(store, { name: "X", amount: -5, accountId: account.id }).ok, false);
    assert.equal(createOpportunity(store, { name: "X", amount: "abc", accountId: account.id }).ok, false);
    assert.equal(createOpportunity(store, { name: "X", probability: 101, accountId: account.id }).ok, false);
    assert.equal(createOpportunity(store, { name: "X", probability: -1, accountId: account.id }).ok, false);
    assert.equal(createOpportunity(store, { name: "X", accountId: "missing" }).ok, false);
    assert.equal(createOpportunity(store, { name: "", accountId: account.id }).ok, false);
    assert.equal(createOpportunity(store, { name: "OK", amount: 0, probability: 100, accountId: account.id }).ok, true);
    assert.equal(createAccount(store, { name: "" }).ok, false);
  });
});

describe("report aggregation (by-stage + quarterly)", () => {
  it("sums counts and amounts per stage, quarters split by createdAt", () => {
    const { store, mk } = seeded();
    const a = mk("A", 1000, 50, "u-1", "2026-11-05T00:00:00Z"); // 2026-Q4
    const b = mk("B", 500, 100, "u-1", "2026-02-10T00:00:00Z"); // 2026-Q1
    const c = mk("C", 200, 25, "u-2", "2026-11-20T00:00:00Z"); // 2026-Q4
    transitionOpportunity(store, a.id, "negotiation");
    transitionOpportunity(store, b.id, "won");
    const report = reportOpportunities([...store.opportunities.values()]);
    const byStage = Object.fromEntries(report.byStage.map((r) => [r.stage, r]));
    assert.equal(byStage.negotiation.count, 1);
    assert.equal(byStage.negotiation.amountTotal, 1000);
    assert.equal(byStage.negotiation.weightedTotal, 500);
    assert.equal(byStage.won.count, 1);
    assert.equal(byStage.won.weightedTotal, 500);
    assert.equal(byStage.prospecting.count, 1);
    assert.equal(byStage.prospecting.amountTotal, 200);
    assert.equal(byStage.prospecting.weightedTotal, 50);
    assert.deepEqual(
      report.quarterly.map((r) => [r.quarter, r.count, r.amountTotal]),
      [["2026-Q1", 1, 500], ["2026-Q4", 2, 1200]],
    );
    assert.equal(report.quarterly[1].weightedTotal, 550);
    assert.ok(c.id);
  });
});

describe("role-scoped visibility", () => {
  it("owner sees all, member sees only own, member without userId sees none", () => {
    const { store, mk } = seeded();
    mk("A", 100, 10, "u-1", "2026-11-01T00:00:00Z");
    mk("B", 100, 10, "u-2", "2026-11-01T00:00:00Z");
    const all = [...store.opportunities.values()];
    assert.equal(scopeOpportunities(all, { role: "owner" }).length, 2);
    assert.equal(scopeOpportunities(all, { role: "member", userId: "u-1" }).length, 1);
    assert.equal(scopeOpportunities(all, { role: "member", userId: "u-1" })[0].ownerId, "u-1");
    assert.equal(scopeOpportunities(all, { role: "member" }).length, 0);
    assert.equal(scopeOpportunities(all, { role: "bogus", userId: "u-2" }).length, 1);
    // listOpportunities honors role + stage together
    transitionOpportunity(store, all[0].id, "proposal");
    assert.equal(listOpportunities(store, { role: "member", userId: "u-1", stage: "proposal" }).length, 1);
    assert.equal(listOpportunities(store, { role: "member", userId: "u-2", stage: "proposal" }).length, 0);
    assert.equal(listOpportunities(store, { role: "owner", stage: "prospecting" }).length, 1);
  });
});
