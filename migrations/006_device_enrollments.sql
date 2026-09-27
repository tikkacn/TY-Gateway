-- Apply to the TY Gateway database before enabling allowlisted/activation-required registration.
-- Codes are never stored in plaintext. Existing device rows and FRP mappings are untouched.
CREATE TABLE IF NOT EXISTS device_enrollments (
  serial VARCHAR(32) NOT NULL PRIMARY KEY,
  mac VARCHAR(17) NOT NULL,
  token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  note VARCHAR(255) NOT NULL DEFAULT '',
  profile VARCHAR(64) NOT NULL DEFAULT 'gfw_precise',
  subscription_id CHAR(32) NULL,
  expires_at DATETIME(6) NOT NULL,
  claimed_at DATETIME(6) NULL,
  device_id CHAR(32) NULL,
  created_at DATETIME(6) NOT NULL,
  KEY idx_enrollment_expiry (expires_at),
  KEY idx_enrollment_subscription (subscription_id, claimed_at),
  CONSTRAINT fk_enrollment_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL,
  CONSTRAINT fk_enrollment_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL
);
