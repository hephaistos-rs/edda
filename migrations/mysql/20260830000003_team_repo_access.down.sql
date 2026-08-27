-- Reverses `20260830000003_team_repo_access.up.sql`. Verified end-to-end
-- against a real `mariadb:12.3.3` instance. `idx_repo_access_subject`
-- (added by the up migration) is deliberately left in place rather than
-- dropped: dropping the `subject_type` column below narrows it in place
-- to a single-column index on the renamed `user_id`, and that narrowed
-- index becomes `fk_repo_access_user`'s required supporting index —
-- MariaDB refuses to drop an index a foreign key still needs, and this
-- index is what the original `20260824000003_repo_access` migration's own
-- `CREATE INDEX idx_repo_access_repository_id` (still present throughout,
-- untouched by this migration group) would otherwise have to duplicate.
DELETE FROM repo_access WHERE subject_type = 'team';
ALTER TABLE repo_access DROP PRIMARY KEY;
ALTER TABLE repo_access DROP COLUMN subject_type;
ALTER TABLE repo_access CHANGE COLUMN subject_id user_id VARCHAR(36) NOT NULL;
ALTER TABLE repo_access ADD PRIMARY KEY (repository_id, user_id);
ALTER TABLE repo_access ADD CONSTRAINT fk_repo_access_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
