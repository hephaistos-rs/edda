-- Reverts H4: reinstates the same-repository CHECK. Fails if any
-- cross-repository pull request rows exist (they can't satisfy it) — a
-- deliberate consequence of reverting the capability.
ALTER TABLE pull_requests
    ADD CONSTRAINT `CONSTRAINT_1` CHECK (source_repository_id = repository_id);
