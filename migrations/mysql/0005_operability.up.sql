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
--
-- Text columns that decode as `String` through `sqlx::Any` are bounded
-- `VARCHAR`, not `TEXT` (MySQL reports both the same way on the wire).

CREATE TABLE instance_settings (
    setting_key   VARCHAR(64) PRIMARY KEY NOT NULL,
    setting_value VARCHAR(4096) NOT NULL,
    updated_at    BIGINT NOT NULL DEFAULT (UNIX_TIMESTAMP()),
    updated_by    VARCHAR(36)
);

CREATE TABLE scheduled_jobs (
    name             VARCHAR(64) PRIMARY KEY NOT NULL,
    interval_seconds BIGINT NOT NULL,
    enabled          INTEGER NOT NULL DEFAULT 1,
    next_run_at      BIGINT NOT NULL DEFAULT 0,
    last_run_at      BIGINT,
    last_status      VARCHAR(16),
    last_detail      VARCHAR(1024)
);
CREATE INDEX idx_scheduled_jobs_due ON scheduled_jobs(enabled, next_run_at);
