package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"tygateway/internal/ruleseed"
)

type onboardingState struct {
	Enrolled       bool   `json:"enrolled"`
	RulesCached    bool   `json:"rules_cached"`
	NodesValidated bool   `json:"nodes_validated"`
	Prepared       bool   `json:"prepared"`
	SyncRunning    bool   `json:"sync_running"`
	ProxyEnabled   bool   `json:"proxy_enabled"`
	FRPState       string `json:"frp_state"`
	Blocker        string `json:"blocker,omitempty"`
	NodeCount      int    `json:"node_count"`
}

// Prepared means the registered device has a verified, local policy and native
// DAE node inventory. It does not claim active proxying or FRP reachability.
func (a *agent) onboardingStatus() onboardingState {
	state := a.stateValue()
	a.stateMu.RLock()
	out := onboardingState{Enrolled: state.DeviceID != "" && state.DeviceSecret != "", SyncRunning: a.syncRunning, ProxyEnabled: a.localProxyOn, FRPState: a.autoFRPState}
	ready, subID, count := a.policyReady, a.daeSubID, a.daeNodeCount
	a.stateMu.RUnlock()
	snapshot, err := a.loadAppliedSnapshot()
	if err != nil {
		out.Blocker = "configuration_pending"
		return out
	}
	out.RulesCached = len(snapshot.Config.BaseRules) > 0 && (!ruleseed.KnownProfile(snapshot.Config.Profile) || ruleseed.ValidVersion(snapshot.Config.RulePackageVersion))
	out.NodeCount = len(snapshot.Config.Nodes)
	out.NodesValidated = snapshot.SubscriptionID != "" && out.NodeCount > 0 && snapshot.SubscriptionID == subID && count == out.NodeCount
	out.Prepared = out.Enrolled && out.RulesCached && out.NodesValidated && ready
	if snapshot.SubscriptionID == "" {
		out.Blocker = "subscription_missing"
	} else if !out.Prepared {
		out.Blocker = "validation_pending"
	}
	return out
}

type ruleCatalogCache struct {
	DeviceID string          `json:"device_id"`
	Profile  string          `json:"profile"`
	Packages json.RawMessage `json:"packages"`
}

func (a *agent) saveRuleCatalog(profile string, customer []byte) error {
	var state struct {
		Packages json.RawMessage `json:"rule_packages"`
	}
	if err := json.Unmarshal(customer, &state); err != nil {
		return err
	}
	if len(state.Packages) == 0 {
		return nil
	}
	data, err := json.Marshal(ruleCatalogCache{DeviceID: a.stateValue().DeviceID, Profile: profile, Packages: state.Packages})
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(a.stateDir, "rule-catalog.json"), data)
}

func (a *agent) initialCustomerCatalog() json.RawMessage {
	device := a.stateValue()
	profile := ""
	packages, _ := json.Marshal(ruleseed.Catalog())
	if raw, err := os.ReadFile(filepath.Join(a.stateDir, "rule-catalog.json")); err == nil && len(raw) <= 256<<10 {
		var cache ruleCatalogCache
		if json.Unmarshal(raw, &cache) == nil && cache.DeviceID == device.DeviceID && json.Valid(cache.Packages) {
			profile, packages = cache.Profile, cache.Packages
		}
	}
	data, _ := json.Marshal(map[string]any{
		"device":        map[string]any{"id": device.DeviceID, "serial": device.Serial, "profile": profile},
		"rule_packages": json.RawMessage(packages), "nodes": []any{}, "rules": []any{}, "categories": []string{}, "preferences": map[string]string{},
		"initialization_pending": true,
	})
	return data
}
