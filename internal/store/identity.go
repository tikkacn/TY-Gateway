package store

import (
	"context"
	"errors"
	"github.com/go-sql-driver/mysql"
	"time"
	"tygateway/internal/identity"
	"tygateway/internal/model"
)

func identityError(err error) error {
	var e *mysql.MySQLError
	if errors.As(err, &e) && e.Number == 1062 {
		return ErrConflict
	}
	return err
}
func (s *MemoryStore) UpdateIdentity(ctx context.Context, id, name, email, subscriptionID string) (model.Device, error) {
	email, err := identity.NormalizeEmail(email)
	if err != nil {
		return model.Device{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return d, ErrNotFound
	}
	if subscriptionID != "" {
		if _, ok := s.subscriptions[subscriptionID]; !ok {
			return d, ErrNotFound
		}
		if s.subscriptionReserved(subscriptionID) {
			return d, ErrConflict
		}
	}
	for otherID, other := range s.devices {
		if otherID != id && ((email != "" && other.Email == email) || (subscriptionID != "" && other.SubscriptionID == subscriptionID)) {
			return d, ErrConflict
		}
	}
	if d.Email != email {
		d.CustomerSessionVersion++
		delete(s.customerSecrets, id)
	}
	if d.SubscriptionID != subscriptionID {
		delete(s.customerNodePrefs, id)
	}
	d.Name, d.Email, d.SubscriptionID = name, email, subscriptionID
	d.ConfigVersion++
	d.UpdatedAt = time.Now().UTC()
	s.devices[id] = d
	return d, nil
}
func (s *SQLStore) UpdateIdentity(ctx context.Context, id, name, email, subscriptionID string) (model.Device, error) {
	email, err := identity.NormalizeEmail(email)
	if err != nil {
		return model.Device{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return model.Device{}, err
	}
	defer tx.Rollback()
	if err = checkSubscriptionReservation(ctx, tx, subscriptionID); err != nil {
		return model.Device{}, err
	}
	var oldEmail, oldSub string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(email,''),COALESCE(subscription_id,'') FROM devices WHERE id=? FOR UPDATE`, id).Scan(&oldEmail, &oldSub); err != nil {
		return model.Device{}, err
	}
	if oldSub != subscriptionID {
		if _, err = tx.ExecContext(ctx, `DELETE FROM customer_node_preferences WHERE device_id=?`, id); err != nil {
			return model.Device{}, err
		}
	}
	res, err := tx.ExecContext(ctx, `UPDATE devices SET customer_session_version=customer_session_version+IF(?,1,0),customer_access_hash=IF(?,NULL,customer_access_hash),name=?,email=NULLIF(?,''),subscription_id=NULLIF(?,''),config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?`, oldEmail != email, oldEmail != email, name, email, subscriptionID, id)
	if err != nil {
		return model.Device{}, identityError(err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.Device{}, ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO identity_events(device_id,event_type) VALUES (?,'binding_updated')`, id); err != nil {
		return model.Device{}, err
	}
	if err = tx.Commit(); err != nil {
		return model.Device{}, err
	}
	return s.GetDevice(ctx, id)
}
