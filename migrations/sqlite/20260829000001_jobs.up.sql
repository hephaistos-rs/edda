-- Background job queue (design §12.2): a hand-rolled polling table, not a
-- third-party queue crate. `payload` is a JSON-serialized
-- `edda_domain::JobPayload`; `status` transitions
-- pending -> running -> (succeeded | pending [retry] | failed
-- [dead-letter, after max_attempts]). Claimed via a compare-and-swap
-- `UPDATE ... WHERE id = ? AND status = 'pending'` per candidate row
-- (`edda_db::JobRepo::claim_batch`), not a single `UPDATE ... RETURNING`
-- batch statement — MySQL has no `RETURNING` at all, so this follows the
-- same CAS idiom already used for `repo_number_counters`/ref updates
-- rather than relying on a Postgres/SQLite-only feature.
CREATE TABLE jobs (
    id           TEXT PRIMARY KEY NOT NULL,
    payload      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    run_at       INTEGER NOT NULL,
    last_error   TEXT,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch())
) STRICT;

CREATE INDEX idx_jobs_status_run_at ON jobs(status, run_at);
