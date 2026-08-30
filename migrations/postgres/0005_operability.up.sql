-- Phase 12 (operability): two small operator-facing tables.
--
-- `instance_settings` is a typed key/value store for the handful of
-- deployment knobs an administrator may change at runtime without a
-- restart (registration mode, default repository visibility, the welcome
-- banner, whether the instance is private). A row present here overrides
-- the corresponding `EDDA_*` environment default; the domain
-- `instance_settings` module is the validated gate for keys and values.
--
-- `scheduled_jobs` is the fixed-interval maintenance scheduler's state:
-- one row per periodic maintenance task, its interval, when it is next
-- due, and the outcome of its last run. The scheduler seeds the default
-- rows on startup and an admin can disable a task or force it to run now
-- (`next_run_at = 0`).

CREATE TABLE instance_settings (
    setting_key   TEXT PRIMARY KEY NOT NULL,
    setting_value TEXT NOT NULL,
    updated_at    BIGINT NOT NULL DEFAULT (extract(epoch from now())::bigint),
    updated_by    TEXT
);

CREATE TABLE scheduled_jobs (
    name             TEXT PRIMARY KEY NOT NULL,
    interval_seconds BIGINT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    next_run_at      BIGINT NOT NULL DEFAULT 0,
    last_run_at      BIGINT,
    last_status      TEXT,
    last_detail      TEXT
);
CREATE INDEX idx_scheduled_jobs_due ON scheduled_jobs(enabled, next_run_at);
