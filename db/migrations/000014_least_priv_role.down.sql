-- Reverse 000014: drop the least-privilege runtime role. Default privileges must
-- be revoked before the role can be dropped (mirrors the iam_rls teardown).
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam_app') THEN
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM iam_app';
    EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM iam_app';
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM iam_app';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM iam_app';
    EXECUTE 'REVOKE USAGE ON SCHEMA public FROM iam_app';
    EXECUTE 'REVOKE iam_rls FROM iam_app';
    EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM iam_app', current_database());
    EXECUTE 'DROP ROLE iam_app';
  END IF;
END $$;
