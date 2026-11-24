-- app-itonami-eigyo D1: sealed objects only (ciphertext + metadata, zero plaintext cols).
-- Rows hold opaque envelopes; search/report runs client-side after decryption.
-- NOTE: sealed_records columns are EXACTLY (id, owner_id, cid, envelope, seq,
-- created_at, updated_at) — identical to kokyaku; do not alter.
-- Change any of these tables only in sync with kokyaku (see docs/sfa.md 11.7).
CREATE TABLE sealed_records (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, cid TEXT, envelope TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(owner_id, seq));
CREATE INDEX idx_sealed_owner ON sealed_records(owner_id);
-- Auth: hash-only. Raw nonce/session values are NEVER stored, only SHA-256 hex.
CREATE TABLE challenges (nonce_hash TEXT PRIMARY KEY, did TEXT NOT NULL, purpose TEXT NOT NULL, timestamp TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
CREATE INDEX idx_challenges_did_expires ON challenges(did, expires_at);
CREATE INDEX idx_challenges_created_at ON challenges(created_at);
CREATE TABLE sessions (session_hash TEXT PRIMARY KEY, did TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX idx_sessions_did ON sessions(did);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);
-- Per-owner monotonic seq counter (atomic upsert + RETURNING in the Worker).
CREATE TABLE owner_seq_counters (owner_id TEXT PRIMARY KEY, seq INTEGER NOT NULL);
