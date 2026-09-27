package httpapi

import (
	"context"
	"errors"
	"tygateway/internal/model"
	"tygateway/internal/rules"
	"tygateway/internal/selection"
	"tygateway/internal/subscription"
)

func filterAvailableNodePreferences(prefs map[string]string, nodes []model.Node) map[string]string {
	filtered := make(map[string]string, len(prefs))
	for category, value := range prefs {
		if selection.Valid(value, nodes) {
			filtered[category] = value
		}
	}
	return filtered
}

// Retry when a concurrent mutation would mix a new version with old rules.
func (s *Server) policySnapshot(ctx context.Context, id string) (model.Device, []model.Rule, []model.Node, map[string]string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		d, err := s.Store.GetDevice(ctx, id)
		if err != nil {
			return d, nil, nil, nil, err
		}
		rs, err := s.Store.ListRules(ctx, id)
		if err != nil {
			return d, nil, nil, nil, err
		}
		ns := []model.Node{}
		if d.SubscriptionID != "" {
			ns, err = s.Store.GetSubscriptionNodes(ctx, d.SubscriptionID)
			if err != nil {
				return d, nil, nil, nil, err
			}
		}
		ns = subscription.FilterIPv6NamedNodes(ns)
		prefs, err := s.Store.ListCustomerNodePreferences(ctx, id)
		if err != nil {
			return d, nil, nil, nil, err
		}
		prefs = filterAvailableNodePreferences(prefs, ns)
		next, err := s.Store.GetDevice(ctx, id)
		if err != nil {
			return d, nil, nil, nil, err
		}
		if d.ConfigVersion == next.ConfigVersion {
			if packageNames[d.Profile] != "" {
				p, e := loadRulePackage(d.Profile)
				if e != nil {
					return d, nil, nil, nil, e
				}
				filtered := make([]model.Rule, 0, len(rs)+len(p.Rules))
				for _, rule := range rs {
					if rule.SourceType == "user" || rule.SourceType == "admin" || rule.SourceType == "system" {
						filtered = append(filtered, rule)
					}
				}
				rs = append(filtered, p.Rules...)
				d.RulePackageVersion = p.Version
			}
			return d, rs, ns, prefs, nil
		}
	}
	return model.Device{}, nil, nil, nil, errors.New("configuration changed; retry")
}

func activePolicy(d model.Device, rs []model.Rule, ns []model.Node, prefs map[string]string) []model.Rule {
	return rules.Policy(d, rs, prefs, ns, true)
}
