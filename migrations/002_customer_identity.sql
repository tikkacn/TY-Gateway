-- Reference DDL only. On the existing MySQL 5.7 host, use
-- cmd/ty-identity-migrate instead: it is resumable, decrypts subscriptions
-- in memory to build the keyed lookup digest, checks duplicates, and creates
-- indexes without printing sensitive values. Apply only after a TY database
-- backup and duplicate-binding preflight.
ALTER TABLE devices
 ADD COLUMN name VARCHAR(128) NOT NULL DEFAULT '',
 ADD COLUMN email VARCHAR(254) CHARACTER SET ascii COLLATE ascii_general_ci NULL,
 ADD UNIQUE KEY uq_device_email (email),
 ADD UNIQUE KEY uq_device_subscription (subscription_id);
ALTER TABLE subscriptions ADD COLUMN url_lookup CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL,
 ADD UNIQUE KEY uq_subscription_url (url_lookup);
CREATE TABLE identity_events (
 id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
 device_id CHAR(32) NOT NULL,
 event_type VARCHAR(32) NOT NULL,
 created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
);
