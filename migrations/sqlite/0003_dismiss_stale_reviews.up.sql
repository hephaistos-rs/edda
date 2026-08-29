-- Phase 10: a push to a PR's source branch clears that PR's existing
-- approvals when the target branch's protection rule sets
-- `dismiss_stale_reviews`. A dismissed review stays in the history but no
-- longer counts toward `required_approvals`.
ALTER TABLE pr_reviews ADD COLUMN dismissed_at INTEGER;
