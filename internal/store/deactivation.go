package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/identity"
	"tygateway/internal/model"
)

// DeactivateDevice is an identity reset, not a user-settings reset or disable.
// Approval is retained for a fresh install; the revoked credential can never
// claim again. All changes (including the audit event) commit together.
func (s *MemoryStore) DeactivateDevice(_ context.Context, id string, expected int64, mac string) (model.DeviceEnrollment, error) {
	serial, _, err := identity.NormalizeMAC(mac)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return model.DeviceEnrollment{}, ErrNotFound
	}
	if expected < 1 || d.ConfigVersion != expected || serial != d.Serial {
		return model.DeviceEnrollment{}, ErrConflict
	}
	record, exists := s.deviceEnrollments[serial]
	if exists && (record.DeviceID != id || record.ClaimedAt == nil) {
		return model.DeviceEnrollment{}, ErrConflict
	}
	if d.SubscriptionID != "" && s.subscriptionReserved(d.SubscriptionID) {
		return model.DeviceEnrollment{}, ErrConflict
	}
	baseline, err := enrollmentFields(mac, d.Note, d.Profile, d.SubscriptionID)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	record.DeviceEnrollment = baseline
	now := time.Now().UTC()
	record.ClaimMode, record.ClaimedAt, record.DeviceID = "mac", nil, ""
	record.CreatedAt, record.ExpiresAt = now, now.Add(enrollmentLifetime)
	record.tokenHash = auth.SecretHash(identity.NewSecret())
	s.revokedDeviceSecrets[s.deviceSecrets[id]] = true
	s.deviceEnrollments[serial] = record
	delete(s.devices, id)
	delete(s.deviceSecrets, id)
	delete(s.customerSecrets, id)
	delete(s.customerNodePrefs, id)
	for key, rule := range s.rules {
		if rule.DeviceID == id {
			delete(s.rules, key)
		}
	}
	for key, command := range s.commands {
		if command.DeviceID == id {
			delete(s.commands, key)
		}
	}
	return record.DeviceEnrollment, nil
}

func (s *SQLStore) DeactivateDevice(ctx context.Context, id string, expected int64, mac string) (model.DeviceEnrollment, error) {
	serial, _, err := identity.NormalizeMAC(mac)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	snapshot, err := s.GetDevice(ctx, id)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	if expected < 1 || snapshot.ConfigVersion != expected || serial != snapshot.Serial {
		return model.DeviceEnrollment{}, ErrConflict
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	defer tx.Rollback()
	// Reserve the currently assigned subscription before locking identities,
	// in the same order as preparation/manual binding. Do not restore a stale
	// original reservation that might now belong to another device.
	if err := checkSubscriptionReservation(ctx, tx, snapshot.SubscriptionID); err != nil {
		return model.DeviceEnrollment{}, err
	}
	// Lock enrollment before device, matching registration. A concurrent claim
	// cannot pass the revocation check until this entire reset has committed.
	var record model.DeviceEnrollment
	var claimed sql.NullTime
	var claimedID, sub sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT mac,note,profile,subscription_id,claimed_at,device_id FROM device_enrollments WHERE serial=? FOR UPDATE`, serial).Scan(&record.MAC, &record.Note, &record.Profile, &sub, &claimed, &claimedID)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return model.DeviceEnrollment{}, err
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id=? FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.DeviceEnrollment{}, ErrNotFound
	}
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	if d.SubscriptionID != snapshot.SubscriptionID || d.ConfigVersion != expected || serial != d.Serial || exists && (!claimed.Valid || claimedID.String != id) {
		return model.DeviceEnrollment{}, ErrConflict
	}
	record, err = enrollmentFields(mac, d.Note, d.Profile, d.SubscriptionID)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	now := time.Now().UTC()
	record.MAC, record.ClaimMode = serial, "mac"
	record.CreatedAt, record.ExpiresAt = now, now.Add(enrollmentLifetime)
	var subValue any
	if record.SubscriptionID != "" {
		subValue = record.SubscriptionID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO revoked_device_credentials(secret_hash,device_id,serial,revoked_at) SELECT secret_hash,id,serial,? FROM devices WHERE id=? ON DUPLICATE KEY UPDATE secret_hash=VALUES(secret_hash)`, now, id); err != nil {
		return model.DeviceEnrollment{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO identity_events(device_id,event_type) VALUES (?,'device_deactivated')`, id); err != nil {
		return model.DeviceEnrollment{}, err
	}
	if exists {
		_, err = tx.ExecContext(ctx, `UPDATE device_enrollments SET claim_mode='mac',token_hash=?,note=?,profile=?,subscription_id=?,claimed_at=NULL,device_id=NULL,expires_at=?,created_at=? WHERE serial=?`, auth.SecretHash(identity.NewSecret()), record.Note, record.Profile, subValue, record.ExpiresAt, now, serial)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO device_enrollments(serial,mac,token_hash,claim_mode,note,profile,subscription_id,expires_at,created_at) VALUES (?,?,?,'mac',?,?,?,?,?)`, serial, d.MAC, auth.SecretHash(identity.NewSecret()), record.Note, record.Profile, subValue, record.ExpiresAt, now)
	}
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	// The existing FKs cascade per-device rules, preferences and commands.
	if _, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE id=?`, id); err != nil {
		return model.DeviceEnrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return model.DeviceEnrollment{}, err
	}
	return record, nil
}

func rejectRevokedCredential(ctx context.Context, tx *sql.Tx, secret string) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM revoked_device_credentials WHERE secret_hash=?`, auth.SecretHash(secret)).Scan(&n); err != nil {
		return err // Migration/database failure must fail closed, not admit replay.
	}
	if n != 0 {
		return ErrInvalidActivation
	}
	return nil
}
