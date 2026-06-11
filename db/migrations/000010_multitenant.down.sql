-- Reverse M6 multi-tenant foundation.
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam_rls') THEN
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM iam_rls';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM iam_rls';
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM iam_rls';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM iam_rls';
    EXECUTE 'REVOKE USAGE ON SCHEMA public FROM iam_rls';
    EXECUTE format('REVOKE iam_rls FROM %I', current_user);
    EXECUTE 'DROP ROLE iam_rls';
  END IF;
END $$;

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['roles','user_roles','oauth_clients','api_keys','refresh_tokens','memberships','projects','audit_events','outbox'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
  END LOOP;
END $$;

DROP INDEX IF EXISTS idx_user_roles_lookup;
DROP INDEX IF EXISTS user_roles_unique;
ALTER TABLE user_roles ADD PRIMARY KEY (user_id, role_id);

DROP INDEX IF EXISTS roles_tenant_name;
DROP INDEX IF EXISTS roles_builtin_name;
ALTER TABLE roles ADD CONSTRAINT roles_name_key UNIQUE (name);

ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS project_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE api_keys       DROP COLUMN IF EXISTS project_id;
ALTER TABLE api_keys       DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE outbox         DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE audit_events   DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE oauth_clients  DROP COLUMN IF EXISTS default_project_id;
ALTER TABLE oauth_clients  DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE user_roles     DROP COLUMN IF EXISTS project_id;
ALTER TABLE user_roles     DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE roles          DROP COLUMN IF EXISTS tenant_id;

DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS tenants;
