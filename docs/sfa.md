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
| `src/seal.js` | Client-side sealing: AES-256-GCM encrypt/decrypt of opportunity payloads (key injected, never in repo) |
| `src/worker.js` | Plain-JS Worker: `/health`, yataverse proxy `GET /ipfs/<cid>`, account/opportunity/report routes |
| `schema.sql` | D1 mirror (free tier; not applied) |
| `wrangler.jsonc` | Worker config; D1 binding is a **zero-UUID placeholder (not created)**; **no `r2_buckets`** |
| `package.json` | `test: node --test`, `build: node --check` |
| `test/sfa.test.js`, `test/worker.test.js`, `test/seal.test.js` | `node --test` suites (runnable without install) |

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

> **Superseded by E2EE stage-2 (§11).** The `role`/`userId` query-param trust
> above is **removed**: protected routes now require a verified session and
> the owner scope is the verified DID. The plaintext accounts/opportunities/
> report routes are gone; `src/sfa.js` survives only as the client-side
> library that runs search/report over **decrypted** data.

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

> **Stage-2 surface: see §11.** The plaintext routes below are **removed**;
> the current Worker exposes `/auth/*` + `/records*` (verified sessions,
> sealed envelopes). The statuses shown are the historical skeleton shape.

```text
GET  /health                         {ok, service:"app-itonami-eigyo", storage:"yataverse", r2:false}
GET  /ipfs/<cid>                     yataverse proxy (missing object -> 404 never 500; bad CID -> 400)
POST /accounts   {name}              -> 201 account | 400              (removed)
GET  /accounts?q=                    {items:[…]}                       (removed)
POST /opportunities {name, amount>=0, probability 0..100, accountId, ownerId?} -> 201 | 400 (removed)
GET  /opportunities?q=&stage=&role=&userId=   {items:[…]} (role-scoped)  (removed)
POST /opportunities/:id/transition {to}        -> 200 | 400 | 404        (removed)
GET  /report?role=&userId=&quarter=  {byStage, quarterly, scope}         (removed)
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
npm test     # node --test — transitions, report, roles, yataverse proxy, R2 non-dependence, seal round-trip
npm run build # node --check (no build artifacts)
grep -c '"r2_buckets"' wrangler.jsonc   # must print 0
```

## 10. Threat model & client-side sealing (暗号化）

### 10.1 The threat: CID knowledge is enough to read

`GET https://yataverse.com/ipfs/<cid>` returns the stored body verbatim
with HTTP 200 — yataverse does **not** encrypt content. Anyone who knows
a CID can read the object (public-by-knowledge-of-CID, same as IPFS).
Therefore **unencrypted opportunity data on yataverse has no
confidentiality at all** — a leaked CID, access log, or cache entry is a
full data leak.

### 10.2 The design: encrypt before `yataverse put`

| step | where | what |
|---|---|---|
| 1. Seal | client (browser/app, `src/seal.js`) | AES-256-GCM (`WebCrypto`), random 12-byte IV, AAD `eigyo:opportunity:v1` |
| 2. Put | `yataverse put` (CACAO admin key) | stores the JSON envelope `{v, alg, iv, data}` only |
| 3. Fetch | anyone (`GET /ipfs/<cid>`) | receives ciphertext — unreadable without the key |
| 4. Open | client (`openPayload`) | wrong key / tampered data → AES-GCM auth failure, no plaintext |

```text
opportunity ─▶ seal (client, AES-256-GCM) ─▶ envelope ─▶ yataverse put
opportunity ◀─ open (client, key)      ◀─ GET /ipfs/<cid> (ciphertext only)
```

### 10.3 Key management (outside this dapp)

- Keys are **injected parameters** (`newKey()` / `importKey(raw32)`); no
  key material, password, or seed phrase exists in this repo (tests use
  ephemeral keys generated at runtime).
- Key custody/persistence (keychain, env store, HSM) is an ops decision
  **outside this dapp's scope**. Losing the key = losing the data
  (by design — confidentiality); envelope versioning (`v: 1`) exists for
  future algorithm rotation.
- `src/seal.js` is client-side code: the Worker never receives a key or
  plaintext, and there is intentionally **no seal route** in `src/worker.js`.

### 10.4 Sample-data policy (public repo)

No real opportunity names, customer names, or amounts anywhere in this
repo, docs, or PRs. All tests use synthetic payloads
(`Synthetic Deal Alpha` / `Synthetic Co 000`).

### 10.5 What sealing does NOT cover

- **Metadata**: the CID, existence, and fetch pattern of an envelope are
  still visible to yataverse nodes. Seal hides content, not existence.
- **At-rest copies** on gateways/caches keep the ciphertext (safe), but
  the *ability to fetch* is public — availability is not restricted.
- The in-memory Worker store (skeleton) holds **plaintext**
  opportunities at runtime; it is a local demo surface, not a data
  store. Persisted ciphertext is the sealed envelope, never plaintext.
  *(Stage-2: the plaintext store is retired as a persistence path — §11.3.)*

## 11. E2EE stage-2 — sealed records + did:key auth (owner-approved)

Owner-approved parameters (do not re-decide): PBKDF2-HMAC-SHA256
600,000 iterations + 128-bit header salt; envelope v2 with per-object
DEKs; D1 = ciphertext + metadata only; Awai identity `did:key`
challenge/verify. This section is the stage-2 spec; `src/seal.js`,
`src/worker.js`, `src/auth.js`, `schema.sql`, `test/*.js` implement it.
`kotoba/*` and `MIGRATION-TODO.md` are untouched. No paid resources, no
real D1 database (wrangler keeps the zero-UUID placeholder), **no
`r2_buckets`**.

### 11.1 Envelope v2 (`src/seal.js`)

| part | value |
|---|---|
| KDF | PBKDF2-HMAC-SHA256, **600,000** iterations, **128-bit** random salt in the header (non-secret) |
| DEK | per-object random **256-bit**, AES-256-GCM, one per sealed payload |
| KEK | 256-bit key derived via that KDF from the user passphrase (client only) |
| wrap | DEK wrapped with the KEK (AES-256-GCM), stored as `wrappedKey` |
| AAD | `eigyo:opportunity:v2` (key-wrap uses `eigyo:opportunity:v2:wrap`) |

```json
{ "v": 2, "alg": "AES-256-GCM",
  "iv": "<b64 12B>", "data": "<b64 ciphertext>",
  "wrappedKey": { "alg": "AES-256-GCM", "iv": "<b64 12B>", "data": "<b64 wrapped DEK>" },
  "kdf": { "name": "PBKDF2-HMAC-SHA256", "iterations": 600000, "salt": "<b64 16B>" } }
```

- Rotation = re-wrap DEK only (`rewrapPayload`: data untouched).
- DEK rotation = re-seal (`resealPayload`: fresh DEK + ciphertext).
- v1 → v2 migration (`migrateToV2`: open v1 with the legacy key, re-seal
  as v2). v1 stays openable client-side until migration is done, but
  `POST /records` accepts **v2 only** — v1 is never a new save (review #2).
  Envelopes are rebuilt from allowlisted keys only and validated strictly
  server-side: unknown keys → 400, base64 + fixed lengths
  (iv 12B, salt 16B, wrapped DEK 48B = 32B DEK + 16B GCM tag, data ≥ 16B),
  record id must be server-issued (`record_<32 hex>`) or UUID (review #1).
  KDF is fixed at 600,000 iterations / 16B salt in both the Worker and
  the client `openPayload`/`rewrapPayload` — envelope-supplied iterations
  are never followed (review #3, no 30M-iteration DoS).
- Wrong passphrase / tampered ciphertext → AES-GCM auth failure, no
  plaintext ever returned (negative controls a–d).
- Key-loss = data-loss: if the passphrase/seed is lost, the sealed data is
  **unrecoverable** — there is no reset, no escrow, no server recovery by
  design. Custody is the user's responsibility.

### 11.2 Auth — Awai identity `did:key` (`src/auth.js`, `src/worker.js`)

```text
POST /auth/challenge {did}           -> 201 {did, nonce, purpose, timestamp, expiresAt} | 400 invalid-did | 429 rate-limited (AUTH_RATE_LIMIT binding) | 503 store-unavailable
POST /auth/verify {did, nonce, signature} -> 200 {session, did, expiresAt} | 401 auth-failed | 503 store-unavailable
```

- `did:key:z<base58btc multicodec ed25519-pubkey>` (prefix bytes `ed 01`).
- The client signs the canonical UTF-8 message
  `nonce||purpose||timestamp` (`purpose = eigyo:auth:login`) with its
  Ed25519 private key; the Worker verifies against the public key only.
- Nonces are single-use (consumed on the first verify attempt) and live
  **5 minutes**; sessions are **5-minute** DID-bound sessions presented
  via `x-did` + `x-session` headers (owner decision: no Bearer, same as
  kokyaku; review #5). The session is bound to the presented DID — a
  mismatched `x-did` answers 401. Nonces and sessions are stored in
  **D1** (`env.EIGYO_DB`, tables `challenges` / `sessions`,
  `schema.sql`) — never in isolate-local memory — so any isolate can
  verify. Both tables are **hash-only**: `nonce_hash` / `session_hash`
  hold the SHA-256 hex of the raw value; raw nonces/sessions exist only
  in the challenge/verify responses and are never written to D1.
  Single-use is enforced by one atomic SQL claim —
  `UPDATE challenges SET used = 1 WHERE nonce_hash = ? AND used = 0 AND
  expires_at > ?` — and verify proceeds only when `meta.changes === 1`;
  the claim runs **before** signature verification, so a failed verify
  (bad signature, wrong DID) burns the nonce too, and two parallel
  verifies of the same signature yield exactly one session. Expired
  challenges/sessions are deleted by a sweep on both the challenge and
  verify paths; tables beyond **10,000 rows** are trimmed oldest-first
  by the same sweep (growth is cleaned up, never rejected).
  Unauthenticated challenge issuance is throttled by the
  **`AUTH_RATE_LIMIT` Cloudflare Rate Limiting binding keyed by client
  IP** (`wrangler.jsonc` `ratelimit`, config only — not deployed; the
  IP is never stored in D1). DID-based issuance caps were **removed**:
  a DID is public, so counting it would let a third party lock out its
  owner (and disposable DIDs would lock out everyone). With the binding
  present its decision is passed through as-is; with no binding the
  Worker logs the absence and applies no limit. NO `EIGYO_DB` binding
  → **503** `store-unavailable` on all auth/records routes — the Worker
  never falls back to memory storage. There is no Worker secret for key
  material.
- **Ed25519 choice:** WebCrypto only (`crypto.subtle` Ed25519
  importKey/sign/verify, ~0.05 ms/verify). The former pure-JS BigInt
  implementation is **deleted** (review #4): it measured ~143 ms/verify,
  exceeding the Workers Free 10 ms CPU cap. There is no secret-scalar
  code left anywhere (Kougi K1 — the non-constant-time scalar code is
  gone; signing is platform WebCrypto only). WebCrypto verify in this
  runtime is cofactorless and accepts small-order forgeries, so
  `ed25519Verify` adds explicit public-data checks first: canonical
  encodings (`y < p`, `S < L`) and the libsodium small-order (8-torsion)
  blocklist for both the public key and `R` (Kougi K2 — verified by the
  identity-forgery and `y+p`/`S+L` tests in `test/worker.test.js`).
  Verified against RFC 8032 vectors and cross-checked against native
  Node Ed25519 in `test/worker.test.js`.
- Private keys, passphrases and KEKs **never** reach the Worker — there is
  no Worker secret, log line, or route for them (negative control e).

### 11.3 Storage — D1 `sealed_records` + auth tables (no memory fallback)

`schema.sql` holds `sealed_records` **plus** the auth tables
(`challenges`, `sessions`, `owner_seq_counters`). `sealed_records` is
exactly:

```sql
CREATE TABLE sealed_records (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, cid TEXT, envelope TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(owner_id, seq));
CREATE INDEX idx_sealed_owner ON sealed_records(owner_id);
```

The `UNIQUE(owner_id, seq)` constraint is the backstop for the counter
below: a colliding insert is **retried with a fresh allocation**
(up to 3 attempts) instead of failing the write; a true duplicate id
still answers 409.

- Old `accounts`/`opportunities` tables are removed. The Worker uses
  `env.EIGYO_DB` for every auth and records operation; with no binding
  the auth/records routes answer **503** — the former DEMO in-memory
  fallback is **deleted**, and no production route reads or writes any
  memory store (the only remaining `Map` in `src/auth.js` is the static
  base58 decode table; `src/sfa.js` `createStore` is the client-side
  domain library over decrypted data, not a Worker route).
- `seq` is **server-allocated** from a per-owner counter row
  (`owner_seq_counters`): one atomic upsert
  (`INSERT … ON CONFLICT(owner_id) DO UPDATE SET seq = seq + 1
  RETURNING seq`) hands out the value, so parallel same-owner writes
  always receive distinct `seq`s; `UNIQUE(owner_id, seq)` plus
  retry-on-collision covers a lagging counter. The optional client
  `seq` on `POST /records` is validated for shape (integer ≥ 0) and
  otherwise ignored — the server value is authoritative.
- wrangler.jsonc keeps the zero-UUID placeholder. No real D1 database is
  created; `grep -c '"r2_buckets"' wrangler.jsonc` must print `0`.

### 11.4 Metadata leakage (per column — all non-confidential)

| column | content | confidentiality |
|---|---|---|
| `id` | opaque record key (`record_…`) | non-confidential |
| `owner_id` | the owner's DID (a public identifier) | non-confidential |
| `cid` | content-addressed link, if supplied | non-confidential (blob linkage) |
| `envelope` | the opaque v1/v2 envelope | non-confidential **as ciphertext** (readable only with the passphrase) |
| `seq` | client ordering hint | non-confidential |
| `created_at`, `updated_at` | store-op timestamps | non-confidential (sync pattern only) |

Existence/count of rows, fetch patterns, and timestamps remain visible to
the store operator; content does not (see §10.5).

### 11.5 Records endpoints + client-side search/report

```text
POST /records  (x-did+x-session) {id?, cid?, envelope, seq?} -> 201 metadata | 400 | 401 | 409 | 503
GET  /records  (x-did+x-session) -> 200 {items:[metadata…]} (own DID only) | 401 | 503
GET  /records/:id (x-did+x-session) -> 200 record | 404 | 401 | 400 | 503
GET  /health, GET /ipfs/<cid>    unchanged (missing -> 404 never 500; bad CID -> 400; malformed %-encoding -> 400, never a thrown URIError)
```

- Envelope shape is validated server-side (**v2 only** on POST; rebuilt
  from allowlisted keys — unknown keys → 400); the Worker cannot and
  does not decrypt. Other owners' records answer **404** (existence is
  not leaked). A D1 constraint violation answers **409**; any other D1
  failure answers **503**, never a false 409 (review #6). `seq` in the
  response metadata is the server-allocated per-owner counter value
  (§11.3), never a client-supplied one.
- Server-side plaintext search/report is **removed by design**: `GET
  /records` returns metadata only (never envelopes). The record list is
  what clients fetch; clients decrypt with the passphrase and run
  search/report (`src/sfa.js`) over plaintext locally.

### 11.6 Negative-control tests (synthetic data only)

a–f live in `test/seal.test.js` + `test/worker.test.js`:

a) seal → store/fetch → open matches (`Synthetic Deal Alpha`).
b) wrong passphrase/key fails open, no plaintext returned.
c) 1-byte tamper → AES-GCM auth failure (data and wrappedKey).
d) stored ciphertext contains no plaintext substring (0 hits, decoded bytes too).
e) no key material in repo/logs: source grep (key blocks, secret literals,
   `console.log`, role/userId trust) prints nothing.
f) HTTP contracts preserved: missing object 404 never 500, bad CID 400,
   `wrangler.jsonc` has no `r2_buckets`. Synthetic data only; no real data.

### 11.7 D1 auth store (done — not out of scope any more)

The item-8 TODO is **done**: challenges/sessions moved from isolate-local
`Map`s to D1 (`env.EIGYO_DB`) — hash-only (`nonce_hash`/`session_hash`
= SHA-256 hex, 0 raw values in the DB), atomic single-use via
`UPDATE … WHERE used = 0 AND expires_at > ?` with `meta.changes === 1`
(a failed verify burns the nonce), expiry sweep + oldest-first trim
beyond 10,000 rows on the challenge/verify paths, IP-keyed
`AUTH_RATE_LIMIT` throttling (no DID caps — see §11.2), no binding →
**503** (memory fallback deleted), and server-allocated per-owner
`seq` via `owner_seq_counters` + `UNIQUE(owner_id, seq)` retry.
Negative controls a–f for THIS store live in `test/d1-auth.test.js`
(shared fake D1 in `test/fake-d1.js`); the real `schema.sql` is also
executed under `node:sqlite` in `test/schema-sqlite.test.js` (the
fake does not parse SQL, so this catches statement/schema typos the
fake cannot).

**Shared contract with kokyaku:** eigyo and kokyaku use the identical
`sealed_records` schema (columns `id, owner_id, cid, envelope, seq,
created_at, updated_at` — zero plaintext columns) and the same auth
behavior (`x-did` + `x-session`, 5-minute challenge/session lifetimes,
envelope v2 only, KDF fixed at 600,000). Any change here must be
mirrored in kokyaku (and vice versa) so both stay in sync — this repo
change does not touch any kokyaku repo.

Remaining out of scope:
- No D1 database creation, no paid services, no additional bindings.
- No `kotoba/*` or `MIGRATION-TODO.md` changes.
- No server escrow / password reset (by design — §11.1).
- No server-side full-text search or reports over plaintext (by design — §11.5).
