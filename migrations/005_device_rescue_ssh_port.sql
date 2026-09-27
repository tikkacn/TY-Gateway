-- Add an administrator-managed, unique FRPS SSH remote port per OEC device.
-- Existing rows remain unassigned (NULL) until their actual frpc mapping is recorded.
ALTER TABLE devices
  ADD COLUMN rescue_ssh_port INT UNSIGNED NULL DEFAULT NULL,
  ADD UNIQUE KEY uq_devices_rescue_ssh_port (rescue_ssh_port);
