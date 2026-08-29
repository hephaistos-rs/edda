-- Per-(account, client-IP) failed-login counter for brute-force
-- throttling (`edda_auth::login_throttle`). `attempt_key` is
-- `lower(email) || '|' || client_ip`, so a wrong password for one account
-- from one IP doesn't slow a different account or a different IP. A row is
-- upserted on each failure and deleted (or reset) on a successful login;
-- `locked_until` is set once `failure_count` crosses the threshold, and a
-- login attempt while `now < locked_until` is refused without even
-- checking the password.
CREATE TABLE login_attempts (
    attempt_key     TEXT PRIMARY KEY NOT NULL,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    first_failed_at INTEGER NOT NULL,
    last_failed_at  INTEGER NOT NULL,
    locked_until    INTEGER
) STRICT;
