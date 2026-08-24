-- Four-tier role model (Read/Write/Admin/Owner), replacing the
-- pre-restructuring two-value ('owner'/'collaborator') model where both
-- roles carried identical write access (plan.local.md §4.2/§16 smell S6).
-- `user_id` is a direct foreign key (not the polymorphic pattern
-- `repositories.owner_id` uses) because there is no team/subject-kind
-- widening planned before organizations exist — see plan.local.md §17
-- Phase 7 for where a `subject_type`-style widening would be introduced,
-- deliberately not added now (plan.local.md's own Phase 1 exit criteria
-- call for exactly the features Phase 1 needs, not later phases' shapes
-- pre-added "for convenience").
CREATE TABLE repo_access (
    repository_id TEXT NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role          TEXT NOT NULL CHECK (role IN ('read', 'write', 'admin', 'owner')),
    added_at      INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (repository_id, user_id)
) STRICT;

CREATE INDEX idx_repo_access_repository_id ON repo_access(repository_id);

-- Exactly one Owner grant per repository at all times — the invariant
-- `edda-domain`'s authorization functions assume holds (plan.local.md
-- §4.2).
CREATE UNIQUE INDEX idx_repo_access_one_owner ON repo_access(repository_id) WHERE role = 'owner';
