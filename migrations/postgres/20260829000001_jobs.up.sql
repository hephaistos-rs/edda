-- PostgreSQL counterpart of sqlite/20260829000001_jobs.up.sql.
CREATE TABLE jobs (
    id           TEXT PRIMARY KEY NOT NULL,
    payload      TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    run_at       BIGINT NOT NULL,
    last_error   TEXT,
    created_at   BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint)
);

CREATE INDEX idx_jobs_status_run_at ON jobs(status, run_at);
