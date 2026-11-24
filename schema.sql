-- app-itonami-eigyo D1: sealed objects only (ciphertext + metadata, zero plaintext cols).
-- Rows hold opaque envelopes; search/report runs client-side after decryption.
CREATE TABLE sealed_records (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, cid TEXT, envelope TEXT NOT NULL, seq INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX idx_sealed_owner ON sealed_records(owner_id);
