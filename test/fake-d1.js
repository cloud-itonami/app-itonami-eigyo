// Test-only fake D1: implements the exact SQL statements the Worker issues
// against env.EIGYO_DB, over in-memory tables, with real D1 semantics:
// run() returns { success, meta: { changes } }, first() -> row|null,
// all() -> { success, results }. Mutations happen synchronously inside
// run() (no await before the write), so a single UPDATE is atomic across
// concurrent callers sharing this instance — exactly the property the
// atomic single-use and seq-counter tests rely on. NOT production code.
export function createFakeD1() {
  const tables = {
    challenges: new Map(), // nonce_hash -> row
    sessions: new Map(), // session_hash -> row
    sealed_records: new Map(), // id -> row
    owner_seq_counters: new Map(), // owner_id -> { owner_id, seq }
  };

  function execute(sql, params, mode) {
    const s = sql.replace(/\s+/g, " ").trim();
    // --- expiry sweep ---
    if (s.startsWith("DELETE FROM challenges WHERE expires_at")) {
      const now = params[0];
      let changes = 0;
      for (const [k, row] of tables.challenges) {
        if (row.expires_at <= now) { tables.challenges.delete(k); changes++; }
      }
      return { success: true, meta: { changes } };
    }
    if (s.startsWith("DELETE FROM sessions WHERE expires_at")) {
      const now = params[0];
      let changes = 0;
      for (const [k, row] of tables.sessions) {
        if (row.expires_at <= now) { tables.sessions.delete(k); changes++; }
      }
      return { success: true, meta: { changes } };
    }
    if (s.startsWith("DELETE FROM sessions WHERE session_hash = ?")) {
      const changes = tables.sessions.delete(params[0]) ? 1 : 0;
      return { success: true, meta: { changes } };
    }
    // --- table trim (oldest-first beyond the row cap; never rejects) ---
    if (s.startsWith("DELETE FROM challenges WHERE nonce_hash IN")) {
      const excess = params[0];
      const oldest = [...tables.challenges.values()].sort((a, b) => a.created_at - b.created_at).slice(0, excess);
      for (const row of oldest) tables.challenges.delete(row.nonce_hash);
      return { success: true, meta: { changes: oldest.length } };
    }
    if (s.startsWith("DELETE FROM sessions WHERE session_hash IN")) {
      const excess = params[0];
      const oldest = [...tables.sessions.values()].sort((a, b) => a.created_at - b.created_at).slice(0, excess);
      for (const row of oldest) tables.sessions.delete(row.session_hash);
      return { success: true, meta: { changes: oldest.length } };
    }
    if (s === "SELECT COUNT(*) AS n FROM challenges") {
      return mode === "all" ? { success: true, results: [{ n: tables.challenges.size }] } : { n: tables.challenges.size };
    }
    if (s === "SELECT COUNT(*) AS n FROM sessions") {
      return mode === "all" ? { success: true, results: [{ n: tables.sessions.size }] } : { n: tables.sessions.size };
    }
    // --- challenge issuance caps ---
    if (s.startsWith("SELECT COUNT(*) AS n FROM challenges WHERE did")) {
      const n = [...tables.challenges.values()].filter(
        (r) => r.did === params[0] && r.used === 0 && r.expires_at > params[1],
      ).length;
      return mode === "all" ? { success: true, results: [{ n }] } : { n };
    }
    if (s.startsWith("SELECT COUNT(*) AS n FROM challenges")) {
      const n = [...tables.challenges.values()].filter(
        (r) => r.used === 0 && r.expires_at > params[0],
      ).length;
      return mode === "all" ? { success: true, results: [{ n }] } : { n };
    }
    // --- challenges ---
    if (s.startsWith("INSERT INTO challenges")) {
      // Worker binds 6 params for 7 columns (used is the literal 0).
      const [nonce_hash, did, purpose, timestamp, expires_at, created_at] = params;
      if (tables.challenges.has(nonce_hash)) throw new Error("UNIQUE constraint failed: challenges.nonce_hash");
      tables.challenges.set(nonce_hash, { nonce_hash, did, purpose, timestamp, expires_at, used: 0, created_at });
      return { success: true, meta: { changes: 1 } };
    }
    if (s.startsWith("UPDATE challenges SET used")) {
      // Atomic claim: the check + write happen in one synchronous step.
      const [nonce_hash, now] = params;
      const row = tables.challenges.get(nonce_hash);
      if (!row || row.used !== 0 || !(row.expires_at > now)) {
        return { success: true, meta: { changes: 0 } };
      }
      row.used = 1;
      return { success: true, meta: { changes: 1 } };
    }
    if (s.startsWith("SELECT") && s.includes("FROM challenges WHERE nonce_hash")) {
      const row = tables.challenges.get(params[0]);
      return row ? { ...row } : null;
    }
    // --- sessions ---
    if (s.startsWith("INSERT INTO sessions")) {
      const [session_hash, did, expires_at, created_at] = params;
      if (tables.sessions.has(session_hash)) throw new Error("UNIQUE constraint failed: sessions.session_hash");
      tables.sessions.set(session_hash, { session_hash, did, expires_at, created_at });
      return { success: true, meta: { changes: 1 } };
    }
    if (s.startsWith("SELECT") && s.includes("FROM sessions WHERE session_hash")) {
      const row = tables.sessions.get(params[0]);
      return row ? { ...row } : null;
    }
    // --- per-owner seq counter (atomic upsert + RETURNING) ---
    if (s.startsWith("INSERT INTO owner_seq_counters")) {
      const owner_id = params[0];
      const existing = tables.owner_seq_counters.get(owner_id);
      const seq = existing ? existing.seq + 1 : 1;
      tables.owner_seq_counters.set(owner_id, { owner_id, seq });
      if (mode === "all") return { success: true, results: [{ seq }] };
      return { seq };
    }
    // --- sealed records ---
    if (s.startsWith("INSERT INTO sealed_records")) {
      const [id, owner_id, cid, envelope, seq, created_at, updated_at] = params;
      if (tables.sealed_records.has(id)) throw new Error("UNIQUE constraint failed: sealed_records.id");
      // UNIQUE(owner_id, seq) — mirrors the real schema constraint.
      for (const r of tables.sealed_records.values()) {
        if (r.owner_id === owner_id && r.seq === seq) {
          throw new Error("UNIQUE constraint failed: sealed_records.owner_id, sealed_records.seq");
        }
      }
      tables.sealed_records.set(id, { id, owner_id, cid, envelope, seq, created_at, updated_at });
      return { success: true, meta: { changes: 1 } };
    }
    if (s.startsWith("SELECT") && s.includes("FROM sealed_records WHERE id")) {
      const row = tables.sealed_records.get(params[0]);
      return row ? { ...row } : null;
    }
    if (s.startsWith("SELECT") && s.includes("FROM sealed_records WHERE owner_id")) {
      const results = [...tables.sealed_records.values()]
        .filter((r) => r.owner_id === params[0])
        .sort((a, b) => a.seq - b.seq || String(a.created_at).localeCompare(String(b.created_at)))
        .map((r) => ({ ...r }));
      return { success: true, results };
    }
    throw new Error(`unsupported sql: ${s}`);
  }

  function prepare(sql) {
    const bound = (params) => ({
      _sql: sql,
      _params: params,
      async run() { return execute(sql, params, "run"); },
      async first() { const r = execute(sql, params, "first"); return r && r.success === undefined && r.results ? r.results[0] ?? null : r; },
      async all() { const r = execute(sql, params, "all"); return r.results ? r : { success: true, results: [r] }; },
    });
    return { bind: (...params) => bound(params) };
  }

  return {
    _tables: tables,
    _dump() {
      return JSON.stringify({
        challenges: [...tables.challenges.values()],
        sessions: [...tables.sessions.values()],
        sealed_records: [...tables.sealed_records.values()],
        owner_seq_counters: [...tables.owner_seq_counters.values()],
      });
    },
    prepare,
    async batch(statements) {
      const results = [];
      for (const st of statements) results.push(await st.run());
      return results;
    },
  };
}
