-- PostgreSQL counterpart of sqlite/20260830000002_organization_repository_owner.up.sql.
-- No table rebuild needed here — PostgreSQL supports dropping and
-- re-adding a CHECK constraint directly. `repositories_owner_type_check`
-- is the constraint's auto-generated name (Postgres names an inline
-- `CHECK` on a column `<table>_<column>_check` when no explicit
-- `CONSTRAINT` name was given, which is how the original migration wrote
-- it).
ALTER TABLE repositories DROP CONSTRAINT repositories_owner_type_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_owner_type_check CHECK (owner_type IN ('user', 'organization'));
