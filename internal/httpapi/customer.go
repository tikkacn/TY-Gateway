package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"tygateway/internal/auth"
	"tygateway/internal/customer"
	"tygateway/internal/identity"
	"tygateway/internal/model"
	"tygateway/internal/rules"
	"tygateway/internal/selection"
	"tygateway/internal/store"
	"tygateway/internal/subscription"
)

func (s *Server) issueCustomerAccess(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID string `json:"id"`
	}
	if decodeJSON(r, &v) != nil || strings.TrimSpace(v.ID) == "" {
		writeError(w, 400, "device id required")
		return
	}
	d, token, err := s.Store.RotateCustomerAccess(r.Context(), strings.TrimSpace(v.ID))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "device not found")
		return
	}
	if err != nil {
		writeError(w, 500, "customer access unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"device": d, "access_token": token, "portal_path": "/portal"})
}

func (s *Server) customerLogin(w http.ResponseWriter, r *http.Request) {
	if !s.customerLimits.allow("peer:"+loginPeer(r), 30) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "login rate exceeded")
		return
	}
	var v struct {
		DeviceCode  string `json:"device_code"`
		AccessToken string `json:"access_token"`
	}
	if decodeJSON(r, &v) != nil || len(v.AccessToken) > 256 {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	serial, _, err := identity.NormalizeMAC(v.DeviceCode)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	a, err := s.Store.GetCustomerAuthBySerial(r.Context(), serial)
	if !s.customerLimits.allow("login:"+serial, 10) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "login rate exceeded")
		return
	}
	if err != nil || a.CustomerAccessHash == "" || a.State == model.DeviceDisabled || !auth.VerifySecret(v.AccessToken, a.CustomerAccessHash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	d, err := s.Store.GetDevice(r.Context(), a.ID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	writeJSON(w, 200, map[string]any{"session_token": customer.NewSession(d.ID, a.Version, time.Now().UTC(), s.CustomerSessionKey), "device": d.CustomerView()})
}

func (s *Server) customerAPI(w http.ResponseWriter, r *http.Request, path string) {
	session := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(session), "bearer ") {
		writeError(w, http.StatusUnauthorized, "customer authentication required")
		return
	}
	deviceID, version, err := customer.VerifySession(strings.TrimSpace(session[7:]), time.Now().UTC(), s.CustomerSessionKey)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "customer authentication required")
		return
	}
	d, err := s.Store.GetDevice(r.Context(), deviceID)
	if err != nil || d.State == model.DeviceDisabled || d.CustomerSessionVersion != version {
		writeError(w, http.StatusForbidden, "device unavailable")
		return
	}
	budget, bucket := 120, "read:"
	if r.Method != http.MethodGet {
		budget, bucket = 30, "write:"
	}
	if !s.customerLimits.allow(bucket+d.ID, budget) {
		w.Header().Set("Retry-After", "60")
		writeError(w, 429, "too many requests")
		return
	}
	switch {
	case path == "/customer/rule-package" && r.Method == http.MethodPost:
		s.customerRulePackage(w, r, d)
	case path == "/customer/logout" && r.Method == http.MethodPost:
		if s.Store.RevokeCustomerSessions(r.Context(), d.ID) != nil {
			writeError(w, 503, "logout unavailable")
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	case path == "/customer/me" && r.Method == http.MethodGet:
		s.customerMe(w, r, d)
	case path == "/customer/rules" && r.Method == http.MethodGet:
		s.customerRules(w, r, d)
	case path == "/customer/rules" && r.Method == http.MethodPost:
		s.createCustomerRule(w, r, d)
	case path == "/customer/rules/delete" && r.Method == http.MethodPost:
		s.deleteCustomerRule(w, r, d)
	case path == "/customer/override" && r.Method == http.MethodPost:
		s.setCustomerOverride(w, r, d)
	case path == "/customer/node-preference" && r.Method == http.MethodPost:
		s.setCustomerNodePreference(w, r, d)
	case path == "/customer/action" && r.Method == http.MethodPost:
		s.customerAction(w, r, d)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// deviceCustomerAPI is the device-authenticated bridge used by the local OEC
// manager. It deliberately exposes the same customer-safe operations as the
// browser portal, but never accepts or returns a customer access token. The
// Agent proves device identity with its existing HMAC request and the device
// remains the only scope of every operation.
func (s *Server) deviceCustomerAPI(w http.ResponseWriter, r *http.Request, id, operation string, d model.Device) {
	budget, bucket := 120, "device-customer-read:"
	if r.Method != http.MethodGet {
		budget, bucket = 30, "device-customer-write:"
	}
	if !s.customerLimits.allow(bucket+d.ID, budget) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	switch {
	case operation == "rule-package" && r.Method == http.MethodPost:
		s.customerRulePackage(w, r, d)
	case operation == "settings" && r.Method == http.MethodPost:
		s.replaceCustomerSettings(w, r, d)
	case operation == "me" && r.Method == http.MethodGet:
		s.customerMe(w, r, d)
	case operation == "rules" && r.Method == http.MethodGet:
		s.customerRules(w, r, d)
	case operation == "rules" && r.Method == http.MethodPost:
		s.createCustomerRule(w, r, d)
	case operation == "rules/delete" && r.Method == http.MethodPost:
		s.deleteCustomerRule(w, r, d)
	case operation == "override" && r.Method == http.MethodPost:
		s.setCustomerOverride(w, r, d)
	case operation == "node-preference" && r.Method == http.MethodPost:
		s.setCustomerNodePreference(w, r, d)
	case operation == "action" && r.Method == http.MethodPost:
		s.customerAction(w, r, d)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

type customerState struct {
	RulePackages []map[string]any     `json:"rule_packages,omitempty"`
	Categories   []string             `json:"categories"`
	Device       model.CustomerDevice `json:"device"`
	Rules        []model.Rule         `json:"rules"`
	Nodes        []model.CustomerNode `json:"nodes"`
	Preferences  map[string]string    `json:"preferences"`
}

func (s *Server) customerMe(w http.ResponseWriter, r *http.Request, d model.Device) {
	state, err := s.customerState(r, d)
	if err != nil {
		writeError(w, 503, "customer state unavailable")
		return
	}
	writeJSON(w, 200, state)
}

func (s *Server) customerState(r *http.Request, d model.Device) (customerState, error) {
	rs, err := s.Store.ListCustomerRules(r.Context(), d.ID)
	if err != nil {
		return customerState{}, err
	}
	prefs, err := s.Store.ListCustomerNodePreferences(r.Context(), d.ID)
	if err != nil {
		return customerState{}, err
	}
	nodes := make([]model.CustomerNode, 0)
	availableNodes := []model.Node{}
	if d.SubscriptionID != "" {
		ns, e := s.Store.GetSubscriptionNodes(r.Context(), d.SubscriptionID)
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			return customerState{}, e
		}
		availableNodes = subscription.FilterIPv6NamedNodes(ns)
		for _, n := range availableNodes {
			nodes = append(nodes, model.CustomerNode{ID: n.ID, Name: n.Name, Region: selection.RegionForName(n.Name), Group: n.Group})
		}
	}
	prefs = filterAvailableNodePreferences(prefs, availableNodes)
	d.Online = d.LastSeen != nil && time.Since(*d.LastSeen) < s.OfflineAfter
	categories := []string{}
	if p, e := loadRulePackage(d.Profile); e == nil {
		for _, category := range p.Categories {
			if rules.IsVisibleManagedCategory(category) {
				categories = append(categories, category)
			}
		}
	}
	return customerState{Device: d.CustomerView(), Rules: rs, Nodes: nodes, Preferences: prefs, RulePackages: rulePackageCatalog(), Categories: categories}, nil
}

func (s *Server) customerRules(w http.ResponseWriter, r *http.Request, d model.Device) {
	rs, err := s.Store.ListCustomerRules(r.Context(), d.ID)
	if err != nil {
		writeError(w, 503, "rules unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"rules": rs})
}

func (s *Server) createCustomerRule(w http.ResponseWriter, r *http.Request, d model.Device) {
	var v struct {
		ID         string `json:"id"`
		MatchType  string `json:"match_type"`
		MatchValue string `json:"match_value"`
		Action     string `json:"action"`
	}
	if decodeJSON(r, &v) != nil {
		writeError(w, 400, "invalid rule")
		return
	}
	v.MatchType, v.MatchValue, v.Action = strings.TrimSpace(v.MatchType), strings.TrimSpace(v.MatchValue), strings.TrimSpace(v.Action)
	switch v.MatchType {
	case "domain", "domain_suffix":
		v.MatchValue = strings.TrimSuffix(strings.ToLower(v.MatchValue), ".")
		if !validCustomerDomain(v.MatchValue) {
			writeError(w, 400, "invalid domain rule")
			return
		}
	case "cidr", "ip", "ip_cidr":
		normalized, err := rules.NormalizeIPMatchValue(v.MatchValue)
		if err != nil {
			writeError(w, 400, "invalid IP/CIDR rule")
			return
		}
		v.MatchValue = normalized
	default:
		writeError(w, 400, "unsupported rule type")
		return
	}
	switch v.Action {
	case "DIRECT", "PROXY", "AUTO", "BLOCK":
	default:
		if strings.HasPrefix(v.Action, "NODE:") || strings.HasPrefix(v.Action, "GROUP:") {
			break
		}
		writeError(w, 400, "invalid customer action")
		return
	}
	rule, err := s.Store.SaveCustomerRule(r.Context(), model.Rule{ID: v.ID, Source: "customer", SourceType: "user", MatchType: v.MatchType, MatchValue: v.MatchValue, Action: v.Action, Priority: 100, Enabled: true, DeviceID: d.ID})
	if err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrLimit) {
			writeError(w, 409, "duplicate rule or rule limit reached")
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 404, "rule or node unavailable")
			return
		}
		writeError(w, 500, "rule creation failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"rule": rule})
}

func (s *Server) deleteCustomerRule(w http.ResponseWriter, r *http.Request, d model.Device) {
	var v struct {
		ID string `json:"id"`
	}
	if decodeJSON(r, &v) != nil || strings.TrimSpace(v.ID) == "" {
		writeError(w, 400, "rule id required")
		return
	}
	if err := s.Store.DeleteRuleForDevice(r.Context(), strings.TrimSpace(v.ID), d.ID); err != nil {
		writeError(w, 404, "rule not found")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) setCustomerOverride(w http.ResponseWriter, r *http.Request, d model.Device) {
	var v struct {
		Action          string `json:"action"`
		DurationMinutes int    `json:"duration_minutes"`
	}
	if decodeJSON(r, &v) != nil {
		writeError(w, 400, "invalid override")
		return
	}
	v.Action = strings.ToUpper(strings.TrimSpace(v.Action))
	if v.Action == "" {
		v.DurationMinutes = 0
	} else if (v.Action != "DIRECT" && v.Action != "PROXY") || v.DurationMinutes < 1 || v.DurationMinutes > 360 {
		writeError(w, 400, "临时模式请选择直连或代理，持续时间不能超过 6 小时")
		return
	}
	var until *time.Time
	if v.Action != "" {
		t := time.Now().UTC().Add(time.Duration(v.DurationMinutes) * time.Minute)
		until = &t
	}
	updated, err := s.Store.SetCustomerOverride(r.Context(), d.ID, v.Action, until)
	if err != nil {
		writeError(w, 500, "override unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"device": updated.CustomerView()})
}

func (s *Server) setCustomerNodePreference(w http.ResponseWriter, r *http.Request, d model.Device) {
	var v struct {
		Category string `json:"category"`
		NodeID   string `json:"node_id"`
	}
	if decodeJSON(r, &v) != nil {
		writeError(w, 400, "invalid node preference")
		return
	}
	v.Category, v.NodeID = strings.TrimSpace(v.Category), strings.TrimSpace(v.NodeID)
	if packageNames[d.Profile] != "" {
		p, e := loadRulePackage(d.Profile)
		if e != nil || !contains(p.Categories, v.Category) || !rules.IsVisibleManagedCategory(v.Category) {
			writeError(w, 400, "当前方案不包含这个网站分类")
			return
		}
	}
	if !contains(append(rules.SupportedCategories(), "GFW"), v.Category) || len(v.NodeID) > 64 {
		writeError(w, 400, "invalid rule set or node")
		return
	}
	if v.NodeID != "" {
		ns, err := s.Store.GetSubscriptionNodes(r.Context(), d.SubscriptionID)
		if err != nil && !selection.Valid(v.NodeID, nil) {
			writeError(w, 404, "node is not available for this device")
			return
		}
		if !selection.Valid(v.NodeID, subscription.FilterIPv6NamedNodes(ns)) {
			writeError(w, 404, "node is not available for this device")
			return
		}
	}
	if err := s.Store.SetCustomerNodePreference(r.Context(), d.ID, v.Category, v.NodeID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 404, "node is not available for this device")
		} else {
			writeError(w, 500, "node preference unavailable")
		}
		return
	}
	prefs, err := s.Store.ListCustomerNodePreferences(r.Context(), d.ID)
	if err != nil {
		writeError(w, 503, "preferences unavailable")
		return
	}
	updated, err := s.Store.GetDevice(r.Context(), d.ID)
	if err != nil {
		writeError(w, 503, "device version unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"preferences": prefs, "config_version": updated.ConfigVersion})
}

func (s *Server) customerAction(w http.ResponseWriter, r *http.Request, d model.Device) {
	var v struct {
		Action string `json:"action"`
	}
	if decodeJSON(r, &v) != nil || (v.Action != "reload_config" && v.Action != "report_status") {
		writeError(w, 400, "invalid action")
		return
	}
	c, err := s.Store.EnqueueCommand(r.Context(), model.Command{DeviceID: d.ID, Command: v.Action})
	if err != nil {
		writeError(w, 500, "action unavailable")
		return
	}
	// Do not return the command payload or any administrative record.
	writeJSON(w, 202, map[string]any{"ok": true, "queued": c.Status})
}

func contains(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}
