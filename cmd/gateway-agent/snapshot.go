package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"tygateway/internal/model"
	"tygateway/internal/selection"
)

// An applied snapshot is the single atomic, root-only local source of truth
// for rules, selectable nodes, and the policy that the Agent can reapply.
// It never contains the provider URL, proxy endpoint, or proxy credentials.
type appliedSnapshot struct {
	SubscriptionID string             `json:"subscription_id,omitempty"`
	Config         model.DeviceConfig `json:"config"`
	Customer       json.RawMessage    `json:"customer"`
}

func (a *agent) snapshotPath() string { return filepath.Join(a.stateDir, "applied-snapshot.json") }

func (a *agent) loadAppliedSnapshot() (appliedSnapshot, error) {
	data, err := os.ReadFile(a.snapshotPath())
	if err != nil {
		return appliedSnapshot{}, err
	}
	var snapshot appliedSnapshot
	if json.Unmarshal(data, &snapshot) != nil || snapshot.Config.Device.ID != a.stateValue().DeviceID || snapshot.Config.Profile == "" || !json.Valid(snapshot.Customer) {
		return appliedSnapshot{}, errors.New("invalid local applied snapshot")
	}
	return snapshot, nil
}

func (a *agent) saveAppliedSnapshot(config model.DeviceConfig, customer []byte, subscriptionID string) error {
	config.DaeSubscription = nil
	if subscriptionID != "" && len(config.Nodes) == 0 || subscriptionID == "" && len(config.Nodes) != 0 {
		return errors.New("validated node inventory is missing")
	}
	var safe struct {
		Device model.CustomerDevice `json:"device"`
		Nodes  []model.CustomerNode `json:"nodes"`
	}
	if json.Unmarshal(customer, &safe) != nil || safe.Device.ID != config.Device.ID || safe.Device.ConfigVersion != config.ConfigVersion || len(safe.Nodes) != len(config.Nodes) {
		return errors.New("customer state and policy do not match")
	}
	data, err := json.Marshal(appliedSnapshot{SubscriptionID: subscriptionID, Config: config, Customer: customer})
	if err != nil {
		return err
	}
	return writePrivateFile(a.snapshotPath(), data)
}

func (a *agent) fetchCloudCustomerState(ctx context.Context, config model.DeviceConfig) ([]byte, error) {
	endpoint := "/api/v1/device/" + url.PathEscape(a.stateValue().DeviceID) + "/customer/me"
	data, status, err := a.signedRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil || status != http.StatusOK || len(data) > 256<<10 {
		return nil, errors.New("customer rules unavailable")
	}
	var state struct {
		Device model.CustomerDevice `json:"device"`
	}
	if json.Unmarshal(data, &state) != nil || state.Device.ID != config.Device.ID || state.Device.ConfigVersion != config.ConfigVersion {
		if a.logger != nil {
			a.logger.Printf("config_sync stage=customer_state result=version_mismatch")
		}
		return nil, errors.New("customer rules version does not match configuration")
	}
	return data, nil
}

func stateWithValidatedNodes(customer []byte, nodes []model.CustomerNode) ([]byte, error) {
	var state map[string]json.RawMessage
	if json.Unmarshal(customer, &state) != nil || state == nil {
		return nil, errors.New("invalid customer state")
	}
	validNodes := make([]model.Node, 0, len(nodes))
	for _, node := range nodes {
		validNodes = append(validNodes, model.Node{ID: node.ID, Name: node.Name})
	}
	var prefs map[string]string
	if err := json.Unmarshal(state["preferences"], &prefs); err != nil && len(state["preferences"]) > 0 {
		return nil, errors.New("invalid customer preferences")
	}
	for category, id := range prefs {
		if !selection.Valid(id, validNodes) {
			delete(prefs, category)
		}
	}
	for i := range nodes {
		nodes[i].Region = selection.RegionForName(nodes[i].Name)
	}
	var err error
	if state["nodes"], err = json.Marshal(nodes); err != nil {
		return nil, err
	}
	if state["preferences"], err = json.Marshal(prefs); err != nil {
		return nil, err
	}
	return json.Marshal(state)
}

func safePolicyNodes(nodes []model.CustomerNode) ([]model.Node, error) {
	if len(nodes) > 512 {
		return nil, errors.New("too many validated nodes")
	}
	out := make([]model.Node, 0, len(nodes))
	seenID, seenName := map[string]bool{}, map[string]bool{}
	for _, node := range nodes {
		if node.ID == "" || node.Name == "" || strings.ContainsAny(node.Name, "\r\n\x00") || seenID[node.ID] || seenName[node.Name] {
			return nil, errors.New("invalid validated node inventory")
		}
		seenID[node.ID], seenName[node.Name] = true, true
		out = append(out, model.Node{ID: node.ID, Name: node.Name, Protocol: "dae"})
	}
	return out, nil
}

func customerNodes(nodes []model.Node) []model.CustomerNode {
	out := make([]model.CustomerNode, 0, len(nodes))
	for _, node := range nodes {
		out = append(out, model.CustomerNode{ID: node.ID, Name: node.Name, Region: selection.RegionForName(node.Name)})
	}
	return out
}

// A newly fetched subscription is parsed by dae only during the first apply.
// Until that inventory is known, explicit assignments from an older Cloud
// cache must not become empty dae groups. The next pull can restore valid
// selections using the newly reported inventory.
func safeCompiledNodeActions(rules []model.CompiledRule, nodes []model.CustomerNode, unknownInventory bool) []model.CompiledRule {
	ids := make(map[string]bool, len(nodes))
	groups := make(map[string]bool)
	available := make([]model.Node, 0, len(nodes))
	for _, node := range nodes {
		ids[node.ID] = true
		available = append(available, model.Node{ID: node.ID, Name: node.Name})
		if node.Group != "" {
			groups[node.Group] = true
		}
	}
	out := append([]model.CompiledRule(nil), rules...)
	for i := range out {
		action := out[i].Action
		if strings.HasPrefix(action, "NODE:") && (unknownInventory || !ids[strings.TrimPrefix(action, "NODE:")]) || strings.HasPrefix(action, "GROUP:") && (unknownInventory || !groups[strings.TrimPrefix(action, "GROUP:")]) || strings.HasPrefix(action, "REGION:") && (unknownInventory || !selection.Valid("@region:"+strings.TrimPrefix(action, "REGION:"), available)) || strings.HasPrefix(action, "FAILOVER:") && (unknownInventory || !selection.Valid("@failover:"+strings.TrimPrefix(action, "FAILOVER:"), available)) {
			out[i].Action = "AUTO"
		}
	}
	return out
}

func (a *agent) reportValidatedNodes(ctx context.Context, subscriptionID string, nodes []model.CustomerNode) error {
	if subscriptionID == "" || len(nodes) == 0 {
		return nil
	}
	body, err := json.Marshal(struct {
		SubscriptionID string               `json:"subscription_id"`
		Nodes          []model.CustomerNode `json:"nodes"`
	}{SubscriptionID: subscriptionID, Nodes: nodes})
	if err != nil {
		return err
	}
	endpoint := "/api/v1/device/" + url.PathEscape(a.stateValue().DeviceID) + "/nodes"
	_, status, err := a.signedRequest(ctx, http.MethodPost, endpoint, body)
	if err != nil || status != http.StatusOK {
		return errors.New("cloud node inventory sync failed")
	}
	return nil
}
