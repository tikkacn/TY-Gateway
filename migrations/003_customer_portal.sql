-- Reference DDL only. Use cmd/ty-identity-migrate on the existing host so
-- this additive migration is checked and can be safely rerun.
ALTER TABLE devices
 ADD COLUMN customer_access_hash CHAR(64) NULL,
 ADD COLUMN customer_override_action VARCHAR(16) NOT NULL DEFAULT '',
 ADD COLUMN customer_override_until DATETIME(6) NULL;
CREATE TABLE customer_node_preferences (
 device_id CHAR(32) NOT NULL,
 category VARCHAR(64) NOT NULL,
 node_id VARCHAR(64) NOT NULL,
 updated_at DATETIME(6) NOT NULL,
 PRIMARY KEY (device_id, category),
 CONSTRAINT fk_customer_pref_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
