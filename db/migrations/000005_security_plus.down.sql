DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS email_verifications;
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_attempts;
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
DELETE FROM permissions WHERE name = 'audit:read';
