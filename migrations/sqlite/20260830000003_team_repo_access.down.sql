-- Reverses the widening: any team-subject grant is dropped first (only
-- `user`-subject rows fit the narrowed `user_id`-only shape).
DELETE FROM repo_access WHERE subject_type = 'team';

CREATE TABLE repo_access_old (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at      INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (repository_id, user_id)
) STRICT;

INSERT INTO repo_access_old (repository_id, user_id, role, added_at)
SELECT repository_id, subject_id, role, added_at FROM repo_access WHERE subject_type = 'user';

DROP TABLE repo_access;
ALTER TABLE repo_access_old RENAME TO repo_access;

CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);
CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(repository_id) WHERE role = 'owner';
