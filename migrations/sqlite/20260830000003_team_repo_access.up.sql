-- Widens `repo_access` from a `user_id`-only grant to a polymorphic
-- `AccessSubject` (`User` or `Team`, Phase 8) — the same table-rebuild
-- procedure as the `organization_repository_owner` migration, for the
-- same reason (SQLite can't drop a `FOREIGN KEY`/change a composite
-- primary key in place). `PRAGMA foreign_keys` is off for the whole
-- migration run (see `edda_db::run_migrations`), so this and the previous
-- migration's rebuilds both run safely in the same startup.
--
-- Every existing row becomes a `subject_type = 'user'` row with `subject_id`
-- set to its old `user_id` — no data loss, no behavior change for any
-- grant that already existed. `subject_id` has no foreign key of its own
-- (it polymorphically targets `users` or `teams` depending on
-- `subject_type`), the same trade-off `repositories.owner_id` already
-- accepts, enforced by application code instead.
CREATE TABLE repo_access_new (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    subject_type  TEXT NOT NULL CHECK (subject_type IN ('user', 'team')),
    subject_id    TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at      INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (repository_id, subject_type, subject_id)
) STRICT;

INSERT INTO repo_access_new (repository_id, subject_type, subject_id, role, added_at)
SELECT repository_id, 'user', user_id, role, added_at FROM repo_access;

DROP TABLE repo_access;
ALTER TABLE repo_access_new RENAME TO repo_access;

CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);
CREATE INDEX idx_repo_access_subject ON repo_access(subject_type, subject_id);

-- Exactly one Owner grant per repository at all times — unchanged
-- invariant, now covering both subject kinds (an organization-owned
-- repository's `Owner` grant targets its Owners team; see
-- `RepositoryRepo::insert_with_owner_team`).
CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(repository_id) WHERE role = 'owner';
