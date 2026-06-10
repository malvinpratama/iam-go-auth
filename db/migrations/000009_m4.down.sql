DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS totp_recovery_codes;
DROP INDEX IF EXISTS idx_users_deleted_at;
ALTER TABLE users DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE users DROP COLUMN IF EXISTS totp_enabled;
ALTER TABLE users DROP COLUMN IF EXISTS totp_secret;
