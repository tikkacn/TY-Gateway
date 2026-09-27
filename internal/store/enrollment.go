package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"tygateway/internal/auth"
	"tygateway/internal/identity"
	"tygateway/internal/model"
)

const enrollmentLifetime = 30 * 24 * time.Hour

func enrollmentFields(mac, note, profile, subscriptionID string) (model.DeviceEnrollment, error) {
	serial, _, err := identity.NormalizeMAC(mac)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > 255 {
		return model.DeviceEnrollment{}, ErrLimit
	}
	profile = strings.TrimSpace(profile)
	if profile == "" {
		profile = "gfw_precise"
	}
	if len(profile) > 64 {
		return model.DeviceEnrollment{}, ErrLimit
	}
	now := time.Now().UTC()
	return model.DeviceEnrollment{MAC: serial, ClaimMode: "activation", Note: note, Profile: profile, SubscriptionID: strings.TrimSpace(subscriptionID), CreatedAt: now, ExpiresAt: now.Add(enrollmentLifetime)}, nil
}

func validActivation(hash, code string) bool {
	return len(code) == 64 && subtle.ConstantTimeCompare([]byte(hash), []byte(auth.SecretHash(code))) == 1
}

func validDeviceSecret(secret string) bool {
	if len(secret) != 64 {
		return false
	}
	_, err := hex.DecodeString(secret)
	return err == nil
}

func (s *MemoryStore) subscriptionReserved(subscriptionID string) bool {
	for _, enrollment := range s.deviceEnrollments {
		if enrollment.SubscriptionID == subscriptionID && enrollment.ClaimedAt == nil {
			return true
		}
	}
	return false
}

// Lock the subscription row before checking an unclaimed reservation. Both
// preparation and manual binding use this order so neither can silently
// consume a subscription already promised to another device.
func checkSubscriptionReservation(ctx context.Context, tx *sql.Tx, subscriptionID string) error {
	if subscriptionID == "" {
		return nil
	}
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM subscriptions WHERE id=? FOR UPDATE`, subscriptionID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_enrollments WHERE subscription_id=? AND claimed_at IS NULL`, subscriptionID).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrConflict
	}
	return nil
}

func (s *MemoryStore) PrepareDeviceEnrollment(_ context.Context, mac, note, profile, subscriptionID string) (model.DeviceEnrollment, string, error) {
	record, err := enrollmentFields(mac, note, profile, subscriptionID)
	if err != nil {
		return model.DeviceEnrollment{}, "", err
	}
	subscriptionID = record.SubscriptionID
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.deviceEnrollments[record.MAC]; exists {
		return model.DeviceEnrollment{}, "", ErrConflict
	}
	for _, d := range s.devices {
		if d.Serial == record.MAC {
			return model.DeviceEnrollment{}, "", ErrAlreadyRegistered
		}
		if subscriptionID != "" && d.SubscriptionID == subscriptionID {
			return model.DeviceEnrollment{}, "", ErrConflict
		}
	}
	if subscriptionID != "" {
		if _, exists := s.subscriptions[subscriptionID]; !exists {
			return model.DeviceEnrollment{}, "", ErrNotFound
		}
		for _, other := range s.deviceEnrollments {
			if other.SubscriptionID == subscriptionID && other.ClaimedAt == nil {
				return model.DeviceEnrollment{}, "", ErrConflict
			}
		}
	}
	code := identity.NewSecret()
	s.deviceEnrollments[record.MAC] = memoryEnrollment{DeviceEnrollment: record, tokenHash: auth.SecretHash(code)}
	return record, code, nil
}

// PrepareMACDeviceEnrollment creates an allowlist-only preparation. The MAC
// is an identifier, not a secret; the first claimant gets a random durable
// device secret and an atomic first-claim wins binding.
func (s *MemoryStore) PrepareMACDeviceEnrollment(_ context.Context, mac, note, profile, subscriptionID string) (model.DeviceEnrollment, error) {
	record, err := enrollmentFields(mac, note, profile, subscriptionID)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	record.ClaimMode = "mac"
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.deviceEnrollments[record.MAC]; exists {
		return model.DeviceEnrollment{}, ErrConflict
	}
	for _, d := range s.devices {
		if d.Serial == record.MAC {
			return model.DeviceEnrollment{}, ErrAlreadyRegistered
		}
		if record.SubscriptionID != "" && d.SubscriptionID == record.SubscriptionID {
			return model.DeviceEnrollment{}, ErrConflict
		}
	}
	if record.SubscriptionID != "" {
		if _, exists := s.subscriptions[record.SubscriptionID]; !exists {
			return model.DeviceEnrollment{}, ErrNotFound
		}
		for _, other := range s.deviceEnrollments {
			if other.SubscriptionID == record.SubscriptionID && other.ClaimedAt == nil {
				return model.DeviceEnrollment{}, ErrConflict
			}
		}
	}
	s.deviceEnrollments[record.MAC] = memoryEnrollment{DeviceEnrollment: record, tokenHash: auth.SecretHash(identity.NewSecret())}
	return record, nil
}

func (s *MemoryStore) ListDeviceEnrollments(_ context.Context) ([]model.DeviceEnrollment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.DeviceEnrollment, 0, len(s.deviceEnrollments))
	for _, v := range s.deviceEnrollments {
		out = append(out, v.DeviceEnrollment)
	}
	return out, nil
}

func (s *MemoryStore) RevokeDeviceEnrollment(_ context.Context, mac string) error {
	serial, _, err := identity.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.deviceEnrollments[serial]
	if !exists {
		return ErrNotFound
	}
	if record.ClaimedAt != nil {
		return ErrConflict
	}
	delete(s.deviceEnrollments, serial)
	return nil
}

func (s *MemoryStore) RegisterApprovedDevice(_ context.Context, in model.RegisterDeviceInput) (model.Device, string, error) {
	serial, mac, err := identity.NormalizeMAC(in.MAC)
	if err != nil {
		return model.Device{}, "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.deviceEnrollments[serial]
	if !exists || record.ClaimMode != "activation" || !validDeviceSecret(in.DeviceSecret) || !validActivation(record.tokenHash, in.ActivationCode) {
		return model.Device{}, "", ErrInvalidActivation
	}
	if record.ClaimedAt != nil {
		d, ok := s.devices[record.DeviceID]
		if !ok || subtle.ConstantTimeCompare([]byte(s.deviceSecrets[d.ID]), []byte(auth.SecretHash(in.DeviceSecret))) != 1 {
			return model.Device{}, "", ErrInvalidActivation
		}
		return d, in.DeviceSecret, nil
	}
	if !time.Now().UTC().Before(record.ExpiresAt) {
		return model.Device{}, "", ErrInvalidActivation
	}
	for _, d := range s.devices {
		if d.Serial == serial {
			return model.Device{}, "", ErrAlreadyRegistered
		}
		if record.SubscriptionID != "" && d.SubscriptionID == record.SubscriptionID {
			return model.Device{}, "", ErrConflict
		}
	}
	if record.SubscriptionID != "" {
		if _, ok := s.subscriptions[record.SubscriptionID]; !ok {
			return model.Device{}, "", ErrConflict
		}
	}
	now := time.Now().UTC()
	d := model.Device{ID: identity.NewID(), DeviceNumber: s.nextNumber, Serial: serial, MAC: mac, State: model.DeviceEnabled, Online: true, LastSeen: &now, LastIP: in.IP, FirmwareVersion: in.FirmwareVersion, AgentVersion: in.AgentVersion, KernelVersion: in.KernelVersion, HardwareVersion: in.HardwareVersion, Profile: record.Profile, Note: record.Note, SubscriptionID: record.SubscriptionID, ConfigVersion: 1, CreatedAt: now, UpdatedAt: now}
	secret := in.DeviceSecret
	s.devices[d.ID] = d
	s.deviceSecrets[d.ID] = auth.SecretHash(secret)
	s.nextNumber++
	record.ClaimedAt = &now
	record.DeviceID = d.ID
	s.deviceEnrollments[serial] = record
	return d, secret, nil
}

func (s *MemoryStore) RegisterMACClaim(_ context.Context, in model.RegisterDeviceInput) (model.Device, string, error) {
	serial, mac, err := identity.NormalizeMAC(in.MAC)
	if err != nil {
		return model.Device{}, "", err
	}
	if !validDeviceSecret(in.DeviceSecret) {
		return model.Device{}, "", ErrInvalidActivation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.deviceEnrollments[serial]
	if !exists || record.ClaimMode != "mac" || !time.Now().UTC().Before(record.ExpiresAt) {
		return model.Device{}, "", ErrInvalidActivation
	}
	if record.ClaimedAt != nil {
		d, ok := s.devices[record.DeviceID]
		if !ok || subtle.ConstantTimeCompare([]byte(s.deviceSecrets[d.ID]), []byte(auth.SecretHash(in.DeviceSecret))) != 1 {
			return model.Device{}, "", ErrInvalidActivation
		}
		return d, in.DeviceSecret, nil
	}
	for _, d := range s.devices {
		if d.Serial == serial {
			return model.Device{}, "", ErrAlreadyRegistered
		}
		if record.SubscriptionID != "" && d.SubscriptionID == record.SubscriptionID {
			return model.Device{}, "", ErrConflict
		}
	}
	if record.SubscriptionID != "" {
		if _, ok := s.subscriptions[record.SubscriptionID]; !ok {
			return model.Device{}, "", ErrConflict
		}
	}
	now := time.Now().UTC()
	d := model.Device{ID: identity.NewID(), DeviceNumber: s.nextNumber, Serial: serial, MAC: mac, State: model.DeviceEnabled, Online: true, LastSeen: &now, LastIP: in.IP, FirmwareVersion: in.FirmwareVersion, AgentVersion: in.AgentVersion, KernelVersion: in.KernelVersion, HardwareVersion: in.HardwareVersion, Profile: record.Profile, Note: record.Note, SubscriptionID: record.SubscriptionID, ConfigVersion: 1, CreatedAt: now, UpdatedAt: now}
	s.devices[d.ID] = d
	s.deviceSecrets[d.ID] = auth.SecretHash(in.DeviceSecret)
	s.nextNumber++
	record.ClaimedAt, record.DeviceID = &now, d.ID
	s.deviceEnrollments[serial] = record
	return d, in.DeviceSecret, nil
}

func (s *SQLStore) PrepareDeviceEnrollment(ctx context.Context, mac, note, profile, subscriptionID string) (model.DeviceEnrollment, string, error) {
	record, err := enrollmentFields(mac, note, profile, subscriptionID)
	if err != nil {
		return model.DeviceEnrollment{}, "", err
	}
	subscriptionID = record.SubscriptionID
	code := identity.NewSecret()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DeviceEnrollment{}, "", err
	}
	defer tx.Rollback()
	if subscriptionID != "" {
		var id string
		if err = tx.QueryRowContext(ctx, `SELECT id FROM subscriptions WHERE id=? FOR UPDATE`, subscriptionID).Scan(&id); errors.Is(err, sql.ErrNoRows) {
			return model.DeviceEnrollment{}, "", ErrNotFound
		} else if err != nil {
			return model.DeviceEnrollment{}, "", err
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM devices WHERE subscription_id=?) + (SELECT COUNT(*) FROM device_enrollments WHERE subscription_id=? AND claimed_at IS NULL)`, subscriptionID, subscriptionID).Scan(&count); err != nil {
			return model.DeviceEnrollment{}, "", err
		}
		if count != 0 {
			return model.DeviceEnrollment{}, "", ErrConflict
		}
	}
	var existing int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE serial=?`, record.MAC).Scan(&existing); err != nil {
		return model.DeviceEnrollment{}, "", err
	}
	if existing != 0 {
		return model.DeviceEnrollment{}, "", ErrAlreadyRegistered
	}
	var sub any
	if subscriptionID != "" {
		sub = subscriptionID
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO device_enrollments (serial,mac,token_hash,claim_mode,note,profile,subscription_id,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)`, record.MAC, record.MAC, auth.SecretHash(code), record.ClaimMode, record.Note, record.Profile, sub, record.ExpiresAt, record.CreatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return model.DeviceEnrollment{}, "", ErrConflict
		}
		return model.DeviceEnrollment{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return model.DeviceEnrollment{}, "", err
	}
	return record, code, nil
}

func (s *SQLStore) PrepareMACDeviceEnrollment(ctx context.Context, mac, note, profile, subscriptionID string) (model.DeviceEnrollment, error) {
	record, err := enrollmentFields(mac, note, profile, subscriptionID)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	record.ClaimMode = "mac"
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.DeviceEnrollment{}, err
	}
	defer tx.Rollback()
	if record.SubscriptionID != "" {
		if err = checkSubscriptionReservation(ctx, tx, record.SubscriptionID); err != nil {
			return model.DeviceEnrollment{}, err
		}
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE subscription_id=?`, record.SubscriptionID).Scan(&count); err != nil {
			return model.DeviceEnrollment{}, err
		}
		if count != 0 {
			return model.DeviceEnrollment{}, ErrConflict
		}
	}
	var existing int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE serial=?`, record.MAC).Scan(&existing); err != nil {
		return model.DeviceEnrollment{}, err
	}
	if existing != 0 {
		return model.DeviceEnrollment{}, ErrAlreadyRegistered
	}
	var sub any
	if record.SubscriptionID != "" {
		sub = record.SubscriptionID
	}
	// The random unused hash keeps the legacy NOT NULL column populated; it is
	// never disclosed and claim_mode prevents treating it as an activation code.
	_, err = tx.ExecContext(ctx, `INSERT INTO device_enrollments (serial,mac,token_hash,claim_mode,note,profile,subscription_id,expires_at,created_at) VALUES (?,?,?,?,?,?,?,?,?)`, record.MAC, record.MAC, auth.SecretHash(identity.NewSecret()), record.ClaimMode, record.Note, record.Profile, sub, record.ExpiresAt, record.CreatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return model.DeviceEnrollment{}, ErrConflict
		}
		return model.DeviceEnrollment{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.DeviceEnrollment{}, err
	}
	return record, nil
}

func (s *SQLStore) ListDeviceEnrollments(ctx context.Context) ([]model.DeviceEnrollment, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT mac,claim_mode,note,profile,COALESCE(subscription_id,''),expires_at,claimed_at,COALESCE(device_id,''),created_at FROM device_enrollments ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.DeviceEnrollment, 0)
	for rows.Next() {
		var record model.DeviceEnrollment
		var claimed sql.NullTime
		if err := rows.Scan(&record.MAC, &record.ClaimMode, &record.Note, &record.Profile, &record.SubscriptionID, &record.ExpiresAt, &claimed, &record.DeviceID, &record.CreatedAt); err != nil {
			return nil, err
		}
		if claimed.Valid {
			record.ClaimedAt = &claimed.Time
		}
		out = append(out, record)
	}
	return out, rows.Err()
}

func (s *SQLStore) RevokeDeviceEnrollment(ctx context.Context, mac string) error {
	serial, _, err := identity.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM device_enrollments WHERE serial=? AND claimed_at IS NULL`, serial)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLStore) RegisterApprovedDevice(ctx context.Context, in model.RegisterDeviceInput) (model.Device, string, error) {
	serial, mac, err := identity.NormalizeMAC(in.MAC)
	if err != nil {
		return model.Device{}, "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Device{}, "", err
	}
	defer tx.Rollback()
	var hash, claimMode, note, profile string
	var expiry time.Time
	var claimed sql.NullTime
	var claimedID sql.NullString
	var sub sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT token_hash,claim_mode,note,profile,subscription_id,expires_at,claimed_at,device_id FROM device_enrollments WHERE serial=? FOR UPDATE`, serial).Scan(&hash, &claimMode, &note, &profile, &sub, &expiry, &claimed, &claimedID)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, "", ErrInvalidActivation
	}
	if err != nil {
		return model.Device{}, "", err
	}
	if claimMode != "activation" || !validDeviceSecret(in.DeviceSecret) || !validActivation(hash, in.ActivationCode) {
		return model.Device{}, "", ErrInvalidActivation
	}
	if claimed.Valid {
		var storedHash string
		if !claimedID.Valid || tx.QueryRowContext(ctx, `SELECT secret_hash FROM devices WHERE id=?`, claimedID.String).Scan(&storedHash) != nil || subtle.ConstantTimeCompare([]byte(storedHash), []byte(auth.SecretHash(in.DeviceSecret))) != 1 {
			return model.Device{}, "", ErrInvalidActivation
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id=?`, claimedID.String))
		return d, in.DeviceSecret, err
	}
	if !time.Now().UTC().Before(expiry) {
		return model.Device{}, "", ErrInvalidActivation
	}
	secret, id, now := in.DeviceSecret, identity.NewID(), time.Now().UTC()
	var subValue any
	if sub.Valid {
		subValue = sub.String
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO devices (id,serial,mac,secret_hash,note,state,online,last_seen,last_ip,firmware_version,agent_version,kernel_version,hardware_version,profile,config_version,subscription_id,created_at,updated_at) VALUES (?,?,?,?,?,'enabled',1,?,?,?,?,?,?,?,1,?,?,?)`, id, serial, mac, auth.SecretHash(secret), note, now, in.IP, in.FirmwareVersion, in.AgentVersion, in.KernelVersion, in.HardwareVersion, profile, subValue, now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return model.Device{}, "", ErrConflict
		}
		return model.Device{}, "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE device_enrollments SET claimed_at=?,device_id=? WHERE serial=? AND claimed_at IS NULL`, now, id, serial)
	if err != nil {
		return model.Device{}, "", err
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id=?`, id))
	if err != nil {
		return model.Device{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return model.Device{}, "", err
	}
	return d, secret, nil
}

func (s *SQLStore) RegisterMACClaim(ctx context.Context, in model.RegisterDeviceInput) (model.Device, string, error) {
	serial, mac, err := identity.NormalizeMAC(in.MAC)
	if err != nil {
		return model.Device{}, "", err
	}
	if !validDeviceSecret(in.DeviceSecret) {
		return model.Device{}, "", ErrInvalidActivation
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Device{}, "", err
	}
	defer tx.Rollback()
	var claimMode, note, profile string
	var expiry time.Time
	var claimed sql.NullTime
	var claimedID, sub sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT claim_mode,note,profile,subscription_id,expires_at,claimed_at,device_id FROM device_enrollments WHERE serial=? FOR UPDATE`, serial).Scan(&claimMode, &note, &profile, &sub, &expiry, &claimed, &claimedID)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Device{}, "", ErrInvalidActivation
	}
	if err != nil {
		return model.Device{}, "", err
	}
	if claimMode != "mac" {
		return model.Device{}, "", ErrInvalidActivation
	}
	if claimed.Valid {
		var storedHash string
		if !claimedID.Valid || tx.QueryRowContext(ctx, `SELECT secret_hash FROM devices WHERE id=?`, claimedID.String).Scan(&storedHash) != nil || subtle.ConstantTimeCompare([]byte(storedHash), []byte(auth.SecretHash(in.DeviceSecret))) != 1 {
			return model.Device{}, "", ErrInvalidActivation
		}
		d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id=?`, claimedID.String))
		return d, in.DeviceSecret, err
	}
	if !time.Now().UTC().Before(expiry) {
		return model.Device{}, "", ErrInvalidActivation
	}
	secret, id, now := in.DeviceSecret, identity.NewID(), time.Now().UTC()
	var subValue any
	if sub.Valid {
		subValue = sub.String
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO devices (id,serial,mac,secret_hash,note,state,online,last_seen,last_ip,firmware_version,agent_version,kernel_version,hardware_version,profile,config_version,subscription_id,created_at,updated_at) VALUES (?,?,?,?,?,'enabled',1,?,?,?,?,?,?,?,1,?,?,?)`, id, serial, mac, auth.SecretHash(secret), note, now, in.IP, in.FirmwareVersion, in.AgentVersion, in.KernelVersion, in.HardwareVersion, profile, subValue, now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return model.Device{}, "", ErrConflict
		}
		return model.Device{}, "", err
	}
	result, err := tx.ExecContext(ctx, `UPDATE device_enrollments SET claimed_at=?,device_id=? WHERE serial=? AND claimed_at IS NULL AND claim_mode='mac'`, now, id, serial)
	if err != nil {
		return model.Device{}, "", err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return model.Device{}, "", ErrConflict
	}
	d, err := scanDevice(tx.QueryRowContext(ctx, `SELECT `+deviceColumns+` FROM devices WHERE id=?`, id))
	if err != nil {
		return model.Device{}, "", err
	}
	if err = tx.Commit(); err != nil {
		return model.Device{}, "", err
	}
	return d, secret, nil
}
