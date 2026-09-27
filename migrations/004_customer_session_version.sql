-- Reference migration for MySQL 5.7. Run exactly once if using SQL manually.
-- Prefer cmd/ty-identity-migrate: it checks information_schema and is resumable.
ALTER TABLE devices ADD COLUMN customer_session_version BIGINT NOT NULL DEFAULT 0;
