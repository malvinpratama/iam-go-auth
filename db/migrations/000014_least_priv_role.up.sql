-- Phase 3c (T4): prepare a least-privilege runtime role, `iam_app`, for the
-- application to connect as INSTEAD of the superuser `app`.
--
-- WHY: a Postgres superuser BYPASSES Row-Level Security even with FORCE, so today
-- the tenant_isolation policy only bites inside the iam_rls transactions that
-- withTenant/with_tenant open (Phase 3b). If the connection role is itself a
-- non-superuser, RLS applies to EVERY query by default — real defense in depth.
--
-- This migration only PREPARES the role. It is created NOLOGIN so nothing can
-- connect as it yet; the operator enables login + sets a password at cutover.
-- Cutover is intentionally STAGED — see docs/security/least-privilege-db.md.
-- The fail-closed policy returns zero rows / rejects writes when app.tenant_id is
-- unset, so the app may only connect as iam_app once EVERY access to an
-- RLS-enabled table sets a tenant context. Phase 3b covers the tenant-admin
-- writes; the login / register / refresh / validate / api-key read paths must be
-- wrapped before POSTGRES_USER is pointed at iam_app.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam_app') THEN
    -- Explicitly stripped of every elevated attribute so RLS is never bypassed.
    CREATE ROLE iam_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
  END IF;
END $$;

-- Connect + use the schema, and the same DML surface the app needs at runtime.
DO $$
BEGIN
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO iam_app', current_database());
END $$;
GRANT USAGE ON SCHEMA public TO iam_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO iam_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO iam_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO iam_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO iam_app;

-- iam_app must be able to assume iam_rls (the role withTenant elevates to) so
-- tenant-scoped transactions keep working once the app connects as iam_app.
-- NOINHERIT means iam_app does NOT silently gain iam_rls's grants — it must
-- explicitly SET ROLE iam_rls, which is exactly what withTenant does.
GRANT iam_rls TO iam_app;
