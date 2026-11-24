# SFA skeleton — design & gap record (`feat/sfa-skeleton`)

This doc records what `cloud-itonami/app-itonami-eigyo` already had on
`main`, what was missing, and the design of the added skeleton. The repo is
the SpinApp **"Etzhayyim Eigyo — Salesforce相当の営業活動"**
(`PROJECT.jsonld:7`). Top-level `README.md` is the kotoba reference
implementation's doc and is left untouched; this file is the SFA-skeleton
design note.

## 1. Implemented / missing, with citations (main @ `4e748b2`)

| Task item | State | Evidence |
|---|---|---|
| 商談（opportunity）名称・金額・ステージ | **implemented (kotoba)** | `kotoba/src/deal.ts:38-82` `createDeal` (starts at `prospecting`, `deal.ts:73`); `kotoba/src/types.ts:27-32` stages `prospecting\|proposal\|negotiation\|won\|lost`; `DealRecord` (`types.ts:101-112`) carries `title` / `valueMicros` / `stage` / `ownerDid` / optional `leadId` |
| 商談のステージ遷移 | **implemented (kotoba)** | `kotoba/src/deal.ts:119-141` `advanceDeal`; terminal set `won`/`lost` (`deal.ts:36`), `dealTerminal:<stage>` rejection (`deal.ts:132-134`), unknown stage `invalidStage` (`deal.ts:123-125`) |
| 確度（probability） | **missing** | No `probability`/確度 field on `DealRecord` (`types.ts:101-112`); no weighted aggregation anywhere |
| 案件（account）紐付け | **partial** | `LeadRecord.company` is a bare string (`types.ts:48`), required by `createLead` (`lead.ts:25`); deals link to leads via `leadId` (`types.ts:105`). No standalone account entity |
| レポート（stage別件数・金額合計、四半期） | **missing** | No report/aggregate/quarter code anywhere (repo-wide grep for report/quarter/aggregate: empty) |
| ロール権限（owner/member） | **missing** | Only an `ownerDid` filter in list calls (`deal.ts:110`, `lead.ts:86`); no role concept |
| テスト（遷移・集計・権限） | **implemented but unrunnable** | `kotoba/test/eigyo.test.ts` (9 cases) cannot run: `pnpm install` fails in two stages (`README.md:20-22`, `docs/operator-quickstart.md` step 2); `pnpm test` / `pnpm typecheck` never execute |
| Worker / HTTP 面 | **missing** | No `src/worker.js`, no `wrangler.jsonc`, no HTTP routes |
| R2 非依存 | **already compliant** | `r2_buckets` occurrences: 0 (repo-wide grep); no `R2.` calls |

PRs #1–#3 touched only registry/docs (`MIGRATION-TODO.md`, `blueprint.edn`,
`migration.edn`) — no code changes.

## 2. What this branch adds (nothing existing is modified)

| File | Role |
|---|---|
| `src/sfa.js` | Domain: accounts, opportunities (name/amount/**probability**/stage/account link/owner), stage transitions, by-stage + quarterly report, owner/member scoping |
| `src/worker.js` | Plain-JS Worker: `/health`, yataverse proxy `GET /ipfs/<cid>`, account/opportunity/report routes |
| `schema.sql` | D1 mirror (free tier; not applied) |
| `wrangler.jsonc` | Worker config; D1 binding is a **zero-UUID placeholder (not created)**; **no `r2_buckets`** |
| `package.json` | `test: node --test`, `build: node --check` |
| `test/sfa.test.js`, `test/worker.test.js` | `node --test` suites (runnable without install) |

The stage machine intentionally mirrors the kotoba convention (5 stages,
`won`/`lost` terminal, unknown stage rejected) so the two layers agree;
the new probability/report/role features are additive in this layer only
(`kotoba/src/*` types are untouched).

## 3. Data model

| entity | fields |
|---|---|
| `account` （案件/会社） | `id`, `name`, `createdAt` |
| `opportunity` （商談） | `id`, `name`, `amount` (≥ 0), `probability` (0–100), `stage`, `accountId` (required, must exist), `ownerId`, `createdAt`, `updatedAt` |

## 4. Stage transitions

```text
prospecting ──▶ proposal ──▶ negotiation ──▶ won      (terminal)
     │              │              │
     └──────▶ lost ◀──────────────┘                    (terminal)
```

Rule (mirrors `kotoba/src/deal.ts:123-134`): any non-terminal opportunity
may move to any valid stage; `won`/`lost` are immutable; an unknown stage
answers `unknown-stage`; an unknown id answers `not-found`.

## 5. Permission table (role scope)

| role | sees |
|---|---|
| `owner` | all opportunities (list + report) |
| `member` (default) | only rows with `ownerId === userId`; without `userId`, nothing |
| anything else | treated as `member` |

Auth is a skeleton placeholder — `ownerId`/`userId` arrive as request
fields/query params and are not verified yet. No credentials in repo.

## 6. Report shape

```json
{
  "byStage": [{ "stage": "prospecting", "count": 1, "amountTotal": 200, "weightedTotal": 50 }],
  "quarterly": [{ "quarter": "2026-Q4", "count": 2, "amountTotal": 1200, "weightedTotal": 550 }],
  "scope": { "role": "owner", "userId": "" }
}
```

`weightedTotal = Σ amount × probability / 100`. Quarters are UTC, derived
from `createdAt`. `?quarter=YYYY-Qn` filters the quarterly rows.

## 7. HTTP surface

```text
GET  /health                         {ok, service:"app-itonami-eigyo", storage:"yataverse", r2:false}
GET  /ipfs/<cid>                     yataverse proxy (missing object -> 404 never 500; bad CID -> 400)
POST /accounts   {name}              -> 201 account | 400
GET  /accounts?q=                    {items:[…]}
POST /opportunities {name, amount>=0, probability 0..100, accountId, ownerId?} -> 201 | 400
GET  /opportunities?q=&stage=&role=&userId=   {items:[…]} (role-scoped)
POST /opportunities/:id/transition {to}        -> 200 | 400 | 404
GET  /report?role=&userId=&quarter=  {byStage, quarterly, scope}
```

## 8. Constraints (owner policy 2026-11-23)

- **R2 non-dependence:** no `r2_buckets` binding, no `R2.` calls. Read is
  `GET https://yataverse.com/ipfs/<cid>`, write is `yataverse put` (not a
  route in this skeleton). Missing object → **404, never 500**; bad CID
  (blank / `/` / `\` / `..` / control chars) → **400** before any fetch.
  Proven by `test/worker.test.js` ("R2 non-dependence").
- D1 / KV / DO / secrets are allowed by policy but **none were created**;
  the D1 binding is a zero-UUID placeholder. No paid resources.
- No credentials, keys, or tokens in repo, logs, or PR body. No signed
  binaries / APKs.
- Visibility of this repo (currently public) is **not changed** by this
  branch — that is an owner decision.

## 9. Run / test

```sh
npm test     # node --test — transitions, report, roles, yataverse proxy, R2 non-dependence
npm run build # node --check (no build artifacts)
grep -c '"r2_buckets"' wrangler.jsonc   # must print 0
```
