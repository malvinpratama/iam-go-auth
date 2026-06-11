-- Revoke only the M6.4 tenant/project/member grants from admin (leave the
-- pre-existing admin grants intact).
DELETE FROM role_permissions
WHERE role_id = (SELECT id FROM roles WHERE name = 'admin' AND tenant_id IS NULL)
  AND permission_id IN (
    SELECT id FROM permissions
    WHERE name IN ('tenant:read','tenant:write','project:read','project:write','member:read','member:write')
  );
