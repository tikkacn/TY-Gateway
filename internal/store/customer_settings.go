package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"tygateway/internal/identity"
	"tygateway/internal/model"
	"tygateway/internal/selection"
	"tygateway/internal/subscription"
)

// ReplaceCustomerSettings changes only customer-owned rules, node preferences,
// and the temporary override. The expected version protects against restoring
// a backup over newer administrator policy or another customer's edit.
func (s *MemoryStore) ReplaceCustomerSettings(_ context.Context, deviceID string, expected int64, rules []model.CustomerSettingRule, prefs map[string]string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return 0, ErrNotFound
	}
	if d.ConfigVersion != expected {
		return 0, ErrConflict
	}
	if len(rules) > MaxCustomerRules {
		return 0, ErrLimit
	}
	nodes := subscription.FilterIPv6NamedNodes(s.subscriptionNodes[d.SubscriptionID])
	if err := validateReplacement(rules, prefs, nodes); err != nil {
		return 0, err
	}
	for id, rule := range s.rules {
		if rule.DeviceID == deviceID && rule.Source == "customer" && rule.SourceType == "user" {
			delete(s.rules, id)
		}
	}
	for _, rule := range rules {
		id := identity.NewID()
		s.rules[id] = model.Rule{ID: id, Source: "customer", SourceType: "user", DeviceID: deviceID, MatchType: rule.MatchType, MatchValue: rule.MatchValue, Action: rule.Action, Priority: 100, Enabled: true}
	}
	copyPrefs := make(map[string]string, len(prefs))
	for category, value := range prefs {
		copyPrefs[category] = value
	}
	s.customerNodePrefs[deviceID] = copyPrefs
	d.CustomerOverrideAction, d.CustomerOverrideUntil = "", nil
	d.ConfigVersion++
	d.UpdatedAt = time.Now().UTC()
	s.devices[deviceID] = d
	return d.ConfigVersion, nil
}

func (s *SQLStore) ReplaceCustomerSettings(ctx context.Context, deviceID string, expected int64, rules []model.CustomerSettingRule, prefs map[string]string) (int64, error) {
	if len(rules) > MaxCustomerRules {
		return 0, ErrLimit
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var version int64
	var subscriptionID string
	if err := tx.QueryRowContext(ctx, `SELECT config_version,COALESCE(subscription_id,'') FROM devices WHERE id=? FOR UPDATE`, deviceID).Scan(&version, &subscriptionID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if version != expected {
		return 0, ErrConflict
	}
	nodeRows, err := tx.QueryContext(ctx, `SELECT id,name,group_name FROM subscription_nodes WHERE subscription_id=?`, subscriptionID)
	if err != nil {
		return 0, err
	}
	nodes := []model.Node{}
	for nodeRows.Next() {
		var node model.Node
		if err := nodeRows.Scan(&node.ID, &node.Name, &node.Group); err != nil {
			nodeRows.Close()
			return 0, err
		}
		nodes = append(nodes, node)
	}
	err = nodeRows.Err()
	nodeRows.Close()
	if err != nil {
		return 0, err
	}
	if err := validateReplacement(rules, prefs, subscription.FilterIPv6NamedNodes(nodes)); err != nil {
		return 0, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM rules WHERE device_id=? AND source='customer' AND source_type='user'`, deviceID); err != nil {
		return 0, err
	}
	for _, rule := range rules {
		if _, err = tx.ExecContext(ctx, `INSERT INTO rules(id,source,source_type,match_type,match_value,action,priority,enabled,device_id) VALUES (?,'customer','user',?,?,?,100,1,?)`, identity.NewID(), rule.MatchType, rule.MatchValue, rule.Action, deviceID); err != nil {
			return 0, err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM customer_node_preferences WHERE device_id=?`, deviceID); err != nil {
		return 0, err
	}
	for category, value := range prefs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO customer_node_preferences(device_id,category,node_id,updated_at) VALUES (?,?,?,UTC_TIMESTAMP(6))`, deviceID, category, value); err != nil {
			return 0, err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE devices SET customer_override_action='',customer_override_until=NULL,config_version=config_version+1,updated_at=UTC_TIMESTAMP(6) WHERE id=?`, deviceID); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return version + 1, nil
}

func validateReplacement(rules []model.CustomerSettingRule, prefs map[string]string, nodes []model.Node) error {
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		key := rule.MatchType + "\x00" + rule.MatchValue
		if seen[key] || !validNodeAction(rule.Action, nodes) {
			return ErrConflict
		}
		seen[key] = true
	}
	for _, value := range prefs {
		if value == "" || !selection.Valid(value, nodes) {
			return ErrConflict
		}
	}
	return nil
}
