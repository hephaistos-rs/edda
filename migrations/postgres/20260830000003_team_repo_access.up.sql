-- PostgreSQL counterpart of sqlite/20260830000003_team_repo_access.up.sql.
-- No table rebuild needed — PostgreSQL supports every one of these
-- changes as an in-place `ALTER TABLE`. Constraint names below
-- (`repo_access_pkey`, `repo_access_user_id_fkey`) are Postgres's own
-- auto-generated defaults for the original migration's unnamed primary
-- key and inline `REFERENCES` — confirmed directly against a real
-- instance (`\d repo_access`), not assumed.
ALTER TABLE repo_access RENAME COLUMN user_id TO subject_id;
ALTER TABLE repo_access ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'user';
ALTER TABLE repo_access ALTER COLUMN subject_type DROP DEFAULT;
ALTER TABLE repo_access ADD CONSTRAINT repo_access_subject_type_check CHECK (subject_type IN ('user', 'team'));
ALTER TABLE repo_access DROP CONSTRAINT repo_access_user_id_fkey;
ALTER TABLE repo_access DROP CONSTRAINT repo_access_pkey;
ALTER TABLE repo_access ADD PRIMARY KEY (repository_id, subject_type, subject_id);
CREATE INDEX idx_repo_access_subject ON repo_access(subject_type, subject_id);
