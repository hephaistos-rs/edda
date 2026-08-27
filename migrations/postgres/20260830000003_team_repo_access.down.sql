DELETE FROM repo_access WHERE subject_type = 'team';
DROP INDEX idx_repo_access_subject;
ALTER TABLE repo_access DROP CONSTRAINT repo_access_pkey;
ALTER TABLE repo_access DROP CONSTRAINT repo_access_subject_type_check;
ALTER TABLE repo_access DROP COLUMN subject_type;
ALTER TABLE repo_access RENAME COLUMN subject_id TO user_id;
ALTER TABLE repo_access ADD PRIMARY KEY (repository_id, user_id);
ALTER TABLE repo_access ADD CONSTRAINT repo_access_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
