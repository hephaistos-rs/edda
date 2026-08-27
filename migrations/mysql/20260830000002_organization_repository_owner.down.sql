DELETE FROM repositories WHERE owner_type = 'organization';
ALTER TABLE repositories MODIFY COLUMN owner_type VARCHAR(16) NOT NULL CHECK (owner_type IN ('user'));
