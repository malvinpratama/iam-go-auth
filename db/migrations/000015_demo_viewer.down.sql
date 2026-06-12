-- Remove the demo viewer role (cascades to its role_permissions and any
-- user_roles assignments). The demo user row, if present, is left intact.
DELETE FROM roles WHERE name = 'viewer' AND tenant_id IS NULL;
