-- Refresh-token rotation grace: distinguish a token revoked by *rotation* (it
-- has a successor) from one revoked by *logout* (no successor). A just-rotated
-- token re-presented within a short grace window is the benign concurrent-
-- refresh race (e.g. NextAuth firing several requests at once after the access
-- token expires) — we re-issue instead of treating it as theft and wiping the
-- whole token family. replaced_by holds the hash of the successor token.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS replaced_by TEXT;
