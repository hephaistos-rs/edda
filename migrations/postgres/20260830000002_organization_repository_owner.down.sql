DELETE FROM repositories WHERE owner_type = 'organization';
ALTER TABLE repositories DROP CONSTRAINT repositories_owner_type_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_owner_type_check CHECK (owner_type IN ('user'));
