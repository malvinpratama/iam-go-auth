-- name: CreateUser :one
INSERT INTO users (email, password_hash)
VALUES ($1, $2)
RETURNING id, email, status, created_at, updated_at;

-- name: GetUserByEmail :one
SELECT id, email, password_hash, status, email_verified, failed_login_attempts, locked_until, totp_secret, totp_enabled, deleted_at, created_at, updated_at
FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT id, email, password_hash, status, email_verified, failed_login_attempts, locked_until, totp_secret, totp_enabled, deleted_at, created_at, updated_at
FROM users
WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: SoftDeleteUser :exec
UPDATE users SET deleted_at = now(), updated_at = now() WHERE id = $1 AND deleted_at IS NULL;

-- name: RestoreUser :exec
UPDATE users SET deleted_at = NULL, updated_at = now() WHERE id = $1;

-- name: IsUserActive :one
SELECT (deleted_at IS NULL)::boolean FROM users WHERE id = $1;

-- ── 2FA / TOTP (v0.9) ───────────────────────────────────────

-- name: SetTotpSecret :exec
UPDATE users SET totp_secret = $2, totp_enabled = false, updated_at = now() WHERE id = $1;

-- name: EnableTotp :exec
UPDATE users SET totp_enabled = true, updated_at = now() WHERE id = $1;

-- name: DisableTotp :exec
UPDATE users SET totp_secret = NULL, totp_enabled = false, updated_at = now() WHERE id = $1;

-- name: InsertRecoveryCode :exec
INSERT INTO totp_recovery_codes (user_id, code_hash) VALUES ($1, $2);

-- name: DeleteRecoveryCodes :exec
DELETE FROM totp_recovery_codes WHERE user_id = $1;

-- name: ConsumeRecoveryCode :one
UPDATE totp_recovery_codes SET used_at = now()
WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
RETURNING id;

-- ── API keys (v0.9) ─────────────────────────────────────────

-- name: CreateApiKey :exec
INSERT INTO api_keys (id, user_id, key_hash, name, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetApiKeyByHash :one
SELECT id, user_id, scopes, expires_at, revoked_at
FROM api_keys
WHERE key_hash = $1;

-- name: ListApiKeysByUser :many
SELECT id, name, scopes, expires_at, last_used_at, created_at
FROM api_keys
WHERE user_id = $1 AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: RevokeApiKey :exec
UPDATE api_keys SET revoked_at = now()
WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: TouchApiKey :exec
UPDATE api_keys SET last_used_at = now() WHERE id = $1;

-- name: IncrementLoginFailure :one
UPDATE users SET failed_login_attempts = failed_login_attempts + 1
WHERE id = $1
RETURNING failed_login_attempts;

-- name: LockUser :exec
UPDATE users SET locked_until = $2, failed_login_attempts = 0 WHERE id = $1;

-- name: ResetLoginState :exec
UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1;

-- name: MarkEmailVerified :exec
UPDATE users SET email_verified = true WHERE id = $1;

-- name: UpdatePassword :exec
UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1;

-- name: RevokeAllUserRefreshTokens :exec
UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CreateEmailVerification :exec
INSERT INTO email_verifications (token_hash, user_id, expires_at) VALUES ($1, $2, $3);

-- name: ConsumeEmailVerification :one
UPDATE email_verifications SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id;

-- name: CreatePasswordReset :exec
INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1, $2, $3);

-- name: ConsumePasswordReset :one
UPDATE password_resets SET consumed_at = now()
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
RETURNING user_id;

-- name: InsertAuditEvent :exec
INSERT INTO audit_events (actor_id, actor_email, action, target, detail)
VALUES ($1, $2, $3, $4, $5);

-- name: ListAuditEvents :many
SELECT id, actor_id, actor_email, action, target, detail, created_at
FROM audit_events
ORDER BY id DESC
LIMIT $1;

-- name: RevokeAccessJTI :exec
INSERT INTO revoked_tokens (jti, expires_at)
VALUES ($1, $2)
ON CONFLICT (jti) DO NOTHING;

-- name: IsTokenRevoked :one
SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE jti = $1);

-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3)
RETURNING id, user_id, token_hash, expires_at, created_at;

-- name: GetRefreshToken :one
SELECT id, user_id, token_hash, expires_at, revoked_at, created_at
FROM refresh_tokens
WHERE token_hash = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = now()
WHERE token_hash = $1 AND revoked_at IS NULL;

-- name: GetUserPermissions :many
SELECT DISTINCT p.name
FROM user_roles ur
JOIN role_permissions rp ON rp.role_id = ur.role_id
JOIN permissions p ON p.id = rp.permission_id
WHERE ur.user_id = $1
ORDER BY p.name;

-- name: GetUserRoles :many
SELECT r.name
FROM user_roles ur
JOIN roles r ON r.id = ur.role_id
WHERE ur.user_id = $1
ORDER BY r.name;

-- name: GetRoleByName :one
SELECT id, name, description
FROM roles
WHERE name = $1;

-- name: CreateRole :one
INSERT INTO roles (name, description)
VALUES ($1, $2)
RETURNING id, name, description;

-- name: UpdateRole :one
UPDATE roles SET description = $2
WHERE name = $1
RETURNING id, name, description;

-- name: DeleteRole :exec
DELETE FROM roles WHERE name = $1;

-- name: ListRoles :many
SELECT id, name, description
FROM roles
ORDER BY name;

-- name: ListRolesWithPermissions :many
-- Roles + their permission names in a single query (avoids the N+1 over roles).
SELECT r.id, r.name, r.description,
       COALESCE(array_agg(p.name ORDER BY p.name) FILTER (WHERE p.name IS NOT NULL), '{}')::text[] AS permissions
FROM roles r
LEFT JOIN role_permissions rp ON rp.role_id = r.id
LEFT JOIN permissions p ON p.id = rp.permission_id
GROUP BY r.id, r.name, r.description
ORDER BY r.name;

-- name: ListRolePermissionNames :many
SELECT p.name
FROM role_permissions rp
JOIN permissions p ON p.id = rp.permission_id
WHERE rp.role_id = $1
ORDER BY p.name;

-- name: ListPermissions :many
SELECT id, name, description
FROM permissions
ORDER BY name;

-- name: AssignRoleToUser :exec
INSERT INTO user_roles (user_id, role_id)
SELECT $1, r.id FROM roles r WHERE r.name = $2
ON CONFLICT DO NOTHING;

-- name: RevokeRoleFromUser :exec
DELETE FROM user_roles
WHERE user_id = $1
  AND role_id = (SELECT id FROM roles WHERE name = $2);

-- name: GrantPermissionToRole :exec
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.name = $1 AND p.name = $2
ON CONFLICT DO NOTHING;

-- name: RevokePermissionFromRole :exec
DELETE FROM role_permissions rp
WHERE rp.role_id = (SELECT r.id FROM roles r WHERE r.name = $1)
  AND rp.permission_id = (SELECT p.id FROM permissions p WHERE p.name = $2);

-- ── Transactional outbox ────────────────────────────────────

-- name: InsertOutbox :exec
INSERT INTO outbox (aggregate_id, event_type, payload)
VALUES ($1, $2, $3);

-- name: FetchUnpublishedOutbox :many
SELECT id, aggregate_id, event_type, payload
FROM outbox
WHERE published_at IS NULL
ORDER BY created_at
LIMIT $1;

-- name: MarkOutboxPublished :exec
UPDATE outbox SET published_at = now() WHERE id = $1;
