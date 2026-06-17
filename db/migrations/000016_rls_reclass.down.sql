-- Restore the fail-closed tenant_isolation policy (000013) on the reclassified
-- tables, reverting the permissive policy from the up-migration.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['refresh_tokens','api_keys','oauth_clients','memberships','audit_events','outbox'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I USING (
        tenant_id IS NULL
        OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
      )$f$, t);
  END LOOP;
END $$;
