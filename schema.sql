-- app-itonami-eigyo D1 mirror (free tier). Skeleton only: applied later when
-- the Worker is wired to D1. Content-addressed blobs live on yataverse,
-- never in D1 and never in R2 (owner policy 2026-11-23).
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS opportunities (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  amount REAL NOT NULL DEFAULT 0,
  probability REAL NOT NULL DEFAULT 0,
  stage TEXT NOT NULL DEFAULT 'prospecting'
    CHECK (stage IN ('prospecting','proposal','negotiation','won','lost')),
  account_id TEXT NOT NULL REFERENCES accounts(id),
  owner_id TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_opportunities_stage ON opportunities(stage);
CREATE INDEX IF NOT EXISTS idx_opportunities_owner ON opportunities(owner_id);
