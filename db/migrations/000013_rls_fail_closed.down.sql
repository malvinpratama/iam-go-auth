-- Revert to the permissive-when-unset policy.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['roles','user_roles','oauth_clients','api_keys','refresh_tokens','memberships','projects','audit_events','outbox'] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I USING (
        current_setting('app.tenant_id', true) IS NULL
        OR current_setting('app.tenant_id', true) = ''
        OR tenant_id IS NULL
        OR tenant_id = current_setting('app.tenant_id', true)::uuid
      )$f$, t);
  END LOOP;
END $$;
