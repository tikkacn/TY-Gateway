-- Run this in the existing aaPanel MySQL/MariaDB database selected for TY Cloud.
-- No credentials belong in this file.
CREATE TABLE IF NOT EXISTS subscriptions (
  id CHAR(32) NOT NULL PRIMARY KEY,
  name VARCHAR(128) NOT NULL,
  provider VARCHAR(64) NOT NULL DEFAULT '',
  url_ciphertext BLOB NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  node_count INT UNSIGNED NOT NULL DEFAULT 0,
  last_refresh DATETIME(6) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id CHAR(32) NOT NULL PRIMARY KEY,
  device_number BIGINT UNSIGNED NOT NULL AUTO_INCREMENT UNIQUE,
  serial VARCHAR(32) NOT NULL UNIQUE,
  mac VARCHAR(17) NOT NULL,
  secret_hash CHAR(64) NOT NULL,
  note VARCHAR(255) NOT NULL DEFAULT '',
  state ENUM('pending','enabled','disabled') NOT NULL DEFAULT 'pending',
  online TINYINT(1) NOT NULL DEFAULT 0,
  last_seen DATETIME(6) NULL,
  last_ip VARCHAR(64) NOT NULL DEFAULT '',
  firmware_version VARCHAR(64) NOT NULL DEFAULT '',
  agent_version VARCHAR(64) NOT NULL DEFAULT '',
  kernel_version VARCHAR(128) NOT NULL DEFAULT '',
  hardware_version VARCHAR(128) NOT NULL DEFAULT '',
  profile VARCHAR(64) NOT NULL DEFAULT 'gfw_precise',
  config_version BIGINT UNSIGNED NOT NULL DEFAULT 1,
  subscription_id CHAR(32) NULL,
  created_at DATETIME(6) NOT NULL,
  updated_at DATETIME(6) NOT NULL,
  KEY idx_devices_last_seen (last_seen),
  KEY idx_devices_state (state),
  CONSTRAINT fk_devices_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS rules (
  id CHAR(32) NOT NULL PRIMARY KEY,
  source VARCHAR(128) NOT NULL,
  source_type VARCHAR(32) NOT NULL,
  category VARCHAR(64) NOT NULL DEFAULT '',
  match_type VARCHAR(32) NOT NULL,
  match_value VARCHAR(1024) NOT NULL,
  action VARCHAR(64) NOT NULL,
  priority INT NOT NULL DEFAULT 500,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  device_id CHAR(32) NULL,
  source_ip VARCHAR(64) NOT NULL DEFAULT '',
  source_mac VARCHAR(17) NOT NULL DEFAULT '',
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  KEY idx_rules_lookup (device_id, enabled, priority),
  KEY idx_rules_provider (source_type, source),
  CONSTRAINT fk_rules_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subscription_nodes (
  id VARCHAR(64) NOT NULL,
  subscription_id CHAR(32) NOT NULL,
  name VARCHAR(255) NOT NULL DEFAULT '',
  protocol VARCHAR(32) NOT NULL,
  server VARCHAR(255) NOT NULL,
  port INT NOT NULL DEFAULT 0,
  region VARCHAR(32) NOT NULL DEFAULT '',
  group_name VARCHAR(64) NOT NULL DEFAULT '',
  params_json JSON NULL,
  PRIMARY KEY (subscription_id, id),
  CONSTRAINT fk_nodes_subscription FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS commands (
  id CHAR(32) NOT NULL PRIMARY KEY,
  device_id CHAR(32) NOT NULL,
  command VARCHAR(64) NOT NULL,
  payload TEXT NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'queued',
  created_at DATETIME(6) NOT NULL,
  claimed_at DATETIME(6) NULL,
  acked_at DATETIME(6) NULL,
  KEY idx_commands_poll (device_id, status, created_at),
  CONSTRAINT fk_commands_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);
