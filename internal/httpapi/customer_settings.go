package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"tygateway/internal/model"
	"tygateway/internal/rules"
	"tygateway/internal/selection"
	"tygateway/internal/store"
	"tygateway/internal/subscription"
)

// This device-authenticated endpoint is intentionally absent from customerAPI:
// a browser cloud session cannot atomically replace the complete customer set.
func (s *Server) replaceCustomerSettings(w http.ResponseWriter, r *http.Request, d model.Device) {
	var input struct {
		ExpectedVersion int64                       `json:"expected_version"`
		Rules           []model.CustomerSettingRule `json:"rules"`
		Preferences     map[string]string           `json:"preferences"`
	}
	if decodeJSON(r, &input) != nil || input.ExpectedVersion < 1 || len(input.Rules) > store.MaxCustomerRules || len(input.Preferences) > 32 {
		writeError(w, http.StatusBadRequest, "invalid customer settings")
		return
	}
	available := []model.Node{}
	if d.SubscriptionID != "" {
		nodes, err := s.Store.GetSubscriptionNodes(r.Context(), d.SubscriptionID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusServiceUnavailable, "node inventory unavailable")
			return
		}
		available = subscription.FilterIPv6NamedNodes(nodes)
	}
	seen := map[string]bool{}
	for i := range input.Rules {
		rule := &input.Rules[i]
		rule.MatchType = strings.TrimSpace(rule.MatchType)
		rule.MatchValue = strings.TrimSpace(rule.MatchValue)
		rule.Action = strings.TrimSpace(rule.Action)
		switch rule.MatchType {
		case "domain", "domain_suffix":
			rule.MatchValue = strings.TrimSuffix(strings.ToLower(rule.MatchValue), ".")
			if !validCustomerDomain(rule.MatchValue) {
				writeError(w, 400, "invalid domain rule")
				return
			}
		case "cidr", "ip", "ip_cidr":
			value, err := rules.NormalizeIPMatchValue(rule.MatchValue)
			if err != nil {
				writeError(w, 400, "invalid IP/CIDR rule")
				return
			}
			rule.MatchValue = value
		default:
			writeError(w, 400, "unsupported rule type")
			return
		}
		if len(rule.Action) > 64 || !validRestoredAction(rule.Action, available) {
			writeError(w, 400, "rule action or node unavailable")
			return
		}
		key := rule.MatchType + "\x00" + rule.MatchValue
		if seen[key] {
			writeError(w, 409, "duplicate rule")
			return
		}
		seen[key] = true
	}
	categorySet := map[string]bool{}
	if p, err := loadRulePackage(d.Profile); err == nil {
		for _, name := range p.Categories {
			categorySet[name] = rules.IsVisibleManagedCategory(name)
		}
	} else if packageNames[d.Profile] == "" {
		categorySet["GFW"] = true // legacy built-in profile
	}
	for category, value := range input.Preferences {
		if !categorySet[category] || len(value) > 64 || value == "" || !selection.Valid(value, available) {
			writeError(w, 400, "rule set or node unavailable")
			return
		}
	}
	version, err := s.Store.ReplaceCustomerSettings(r.Context(), d.ID, input.ExpectedVersion, input.Rules, input.Preferences)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "configuration changed; refresh and preview again")
		} else if errors.Is(err, store.ErrLimit) {
			writeError(w, http.StatusBadRequest, "rule limit reached")
		} else {
			writeError(w, http.StatusServiceUnavailable, "customer settings unavailable")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config_version": version})
}

func validRestoredAction(action string, nodes []model.Node) bool {
	switch action {
	case "DIRECT", "PROXY", "AUTO", "BLOCK":
		return true
	}
	if strings.HasPrefix(action, "NODE:") {
		for _, node := range nodes {
			if action == "NODE:"+node.ID {
				return true
			}
		}
	}
	if strings.HasPrefix(action, "GROUP:") {
		for _, node := range nodes {
			if node.Group != "" && action == "GROUP:"+node.Group {
				return true
			}
		}
	}
	return false
}
