-- Distinguish one-time activation records from MAC-preapproved first claims.
-- Existing records remain activation-based; only new MAC allowlist entries use
-- the new mode. This does not modify devices or their FRP mappings.
ALTER TABLE device_enrollments
  ADD COLUMN claim_mode VARCHAR(16) NOT NULL DEFAULT 'activation' AFTER token_hash;

CREATE INDEX idx_enrollment_claim_mode ON device_enrollments (claim_mode, claimed_at, expires_at);
