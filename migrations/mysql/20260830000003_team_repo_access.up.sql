-- MySQL/MariaDB counterpart of sqlite/20260830000003_team_repo_access.up.sql.
-- Verified against a real `mariadb:12.3.3` instance (the full sequence
-- below, run end-to-end against a throwaway copy of this exact table
-- shape, including the generated `owner_marker` column). Dropping
-- `fk_repo_access_user` leaves behind its auto-created supporting index
-- under the same name (MariaDB creates one automatically for a `FOREIGN
-- KEY` column when no other index already covers it) — dropped explicitly
-- since `idx_repo_access_subject` (added below) already covers the same
-- leading column and a lingering duplicate index would be pure waste.
ALTER TABLE repo_access DROP FOREIGN KEY fk_repo_access_user;
ALTER TABLE repo_access CHANGE COLUMN user_id subject_id VARCHAR(36) NOT NULL;
ALTER TABLE repo_access ADD COLUMN subject_type VARCHAR(16) NOT NULL DEFAULT 'user' CHECK (subject_type IN ('user', 'team')) AFTER repository_id;
ALTER TABLE repo_access ALTER COLUMN subject_type DROP DEFAULT;
ALTER TABLE repo_access DROP PRIMARY KEY, ADD PRIMARY KEY (repository_id, subject_type, subject_id);
DROP INDEX fk_repo_access_user ON repo_access;
CREATE INDEX idx_repo_access_subject ON repo_access(subject_type, subject_id);
