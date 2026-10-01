-- Keep only credential hashes, never secrets. No device FK: revocations must
-- survive deletion/re-enrollment and prevent an old pending claim from replaying.
CREATE TABLE IF NOT EXISTS revoked_device_credentials (
  secret_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
  device_id CHAR(32) NOT NULL,
  serial VARCHAR(32) NOT NULL,
  revoked_at DATETIME(6) NOT NULL,
  KEY idx_revoked_device (device_id)
);
