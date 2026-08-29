-- A personal access token's *operation* scope, alongside the existing
-- `repository_scope` (its *repository-set* scope). JSON-serialized
-- `edda_domain::TokenScope` — `"All"` (unscoped, every operation),
-- `"RepoRead"` (clone/fetch + GET /api/v1), or `"RepoWrite"` (also push +
-- mutating /api/v1). Default `"All"` so every token issued before scopes
-- existed keeps working exactly as before.
ALTER TABLE access_tokens ADD COLUMN token_scope TEXT NOT NULL DEFAULT '"All"';
