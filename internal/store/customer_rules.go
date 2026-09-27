package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"tygateway/internal/identity"
	"tygateway/internal/model"
)

const MaxCustomerRules = 200

func validNodeAction(action string, nodes []model.Node) bool {
	if !strings.HasPrefix(action, "NODE:") && !strings.HasPrefix(action, "GROUP:") {
		return true
	}
	for _, n := range nodes {
		if action == "NODE:"+n.ID || (n.Group != "" && action == "GROUP:"+n.Group) {
			return true
		}
	}
	return false
}

// Device row locking makes ownership, quota, duplicate validation and the
// config version update atomic with the rule mutation.
func (s *MemoryStore) SaveCustomerRule(_ context.Context, r model.Rule) (model.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[r.DeviceID]
	if !ok {
		return r, ErrNotFound
	}
	if !validNodeAction(r.Action, s.subscriptionNodes[d.SubscriptionID]) {
		return r, ErrNotFound
	}
	count := 0
	for id, old := range s.rules {
		if old.DeviceID == r.DeviceID && old.Source == "customer" {
			count++
			if id != r.ID && old.MatchType == r.MatchType && old.MatchValue == r.MatchValue {
				return r, ErrConflict
			}
		}
	}
	if r.ID != "" {
		old, ok := s.rules[r.ID]
		if !ok || old.DeviceID != r.DeviceID || old.Source != "customer" {
			return r, ErrNotFound
		}
	} else {
		if count >= MaxCustomerRules {
			return r, ErrLimit
		}
		r.ID = identity.NewID()
	}
	r.Source = "customer"
	r.SourceType = "user"
	r.Enabled = true
	s.rules[r.ID] = r
	d.ConfigVersion++
	s.devices[d.ID] = d
	return r, nil
}
func (s *SQLStore) SaveCustomerRule(ctx context.Context, r model.Rule) (model.Rule, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	var sub string
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(subscription_id,'') FROM devices WHERE id=? FOR UPDATE`, r.DeviceID).Scan(&sub); err != nil {
		return r, err
	}
	if strings.HasPrefix(r.Action, "NODE:") || strings.HasPrefix(r.Action, "GROUP:") {
		column := "id"
		value := strings.TrimPrefix(r.Action, "NODE:")
		if strings.HasPrefix(r.Action, "GROUP:") {
			column = "group_name"
			value = strings.TrimPrefix(r.Action, "GROUP:")
		}
		var n int
		if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM subscription_nodes WHERE subscription_id=? AND `+column+`=?`, sub, value).Scan(&n); err != nil {
			return r, err
		}
		if n == 0 {
			return r, ErrNotFound
		}
	}
	var count, duplicates int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*),COALESCE(SUM(match_type=? AND match_value=? AND id<>?),0) FROM rules WHERE device_id=? AND source='customer'`, r.MatchType, r.MatchValue, r.ID, r.DeviceID).Scan(&count, &duplicates); err != nil {
		return r, err
	}
	if duplicates > 0 {
		return r, ErrConflict
	}
	r.Source = "customer"
	r.SourceType = "user"
	r.Enabled = true
	if r.ID == "" {
		if count >= MaxCustomerRules {
			return r, ErrLimit
		}
		r.ID = identity.NewID()
		_, err = tx.ExecContext(ctx, `INSERT INTO rules(id,source,source_type,match_type,match_value,action,priority,enabled,device_id) VALUES (?,'customer','user',?,?,?,?,1,?)`, r.ID, r.MatchType, r.MatchValue, r.Action, r.Priority, r.DeviceID)
	} else {
		var old string
		err = tx.QueryRowContext(ctx, `SELECT id FROM rules WHERE id=? AND device_id=? AND source='customer'`, r.ID, r.DeviceID).Scan(&old)
		if errors.Is(err, sql.ErrNoRows) {
			return r, ErrNotFound
		}
		if err != nil {
			return r, err
		}
		_, err = tx.ExecContext(ctx, `UPDATE rules SET match_type=?,match_value=?,action=? WHERE id=?`, r.MatchType, r.MatchValue, r.Action, r.ID)
	}
	if err != nil {
		return r, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE devices SET config_version=config_version+1 WHERE id=?`, r.DeviceID); err != nil {
		return r, err
	}
	return r, tx.Commit()
}
