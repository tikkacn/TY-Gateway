package store

import (
	"context"
	"time"
	"tygateway/internal/model"
)

func expireOverride(d *model.Device, now time.Time) bool {
	if d.CustomerOverrideAction != "" && (d.CustomerOverrideUntil == nil || !d.CustomerOverrideUntil.After(now)) {
		d.CustomerOverrideAction = ""
		d.CustomerOverrideUntil = nil
		d.ConfigVersion++
		return true
	}
	return false
}
func (s *MemoryStore) RevokeCustomerSessions(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return ErrNotFound
	}
	d.CustomerSessionVersion++
	s.devices[id] = d
	return nil
}
func (s *SQLStore) RevokeCustomerSessions(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET customer_session_version=customer_session_version+1 WHERE id=?`, id)
	return err
}
func (s *MemoryStore) RecordEvent(_ context.Context, id, event string) error { return nil }
func (s *SQLStore) RecordEvent(ctx context.Context, id, event string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO identity_events(device_id,event_type) VALUES (?,?)`, id, event)
	return err
}
