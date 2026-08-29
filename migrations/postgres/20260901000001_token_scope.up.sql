-- PostgreSQL counterpart of sqlite/20260901000001_token_scope.up.sql.
ALTER TABLE access_tokens ADD COLUMN token_scope TEXT NOT NULL DEFAULT '"All"';
