-- v0.9 (M4): TOTP 2FA, scoped API keys, and soft-delete. All additive.

-- 2FA / TOTP + soft-delete columns on the identity row.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret  TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at   TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);

-- One-time recovery codes (hashed) usable in place of a TOTP code.
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id         BIGSERIAL PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_totp_recovery_user ON totp_recovery_codes(user_id);

-- Scoped, programmatic API keys (iamk_...). Only the SHA-256 hash is stored.
CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,            -- public key id / prefix
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash     TEXT NOT NULL UNIQUE,        -- SHA-256 of the full secret
    name         TEXT NOT NULL,
    scopes       TEXT[] NOT NULL DEFAULT '{}',-- permission subset granted to the key
    expires_at   TIMESTAMPTZ,                 -- NULL = no expiry
    revoked_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
