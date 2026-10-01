package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/selection"
)

// Only provider/profile category rules may be rewritten. Personal rules,
// administrator exceptions and immutable management rules retain their rank.
func selectableRule(rule model.CompiledRule) bool {
	return rule.Category != "" && (rule.SourceType == "provider" || rule.SourceType == "profile") && rule.Action != "BLOCK"
}

func overlayLocalPreferences(config model.DeviceConfig, local map[string]string) model.DeviceConfig {
	config.Rules = append([]model.CompiledRule(nil), config.Rules...)
	config.BaseRules = append([]model.CompiledRule(nil), config.BaseRules...)
	prefs := make(map[string]string, len(config.Preferences)+len(local))
	for category, value := range config.Preferences {
		prefs[category] = value
	}
	for category, value := range local {
		if value == "" {
			delete(prefs, category)
		} else if selection.Valid(value, config.Nodes) {
			prefs[category] = value
		} else {
			prefs[category] = "@proxy"
		}
	}
	apply := func(rs []model.CompiledRule) {
		for i := range rs {
			r := &rs[i]
			value, exists := local[r.Category]
			if !exists || !selectableRule(*r) {
				continue
			}
			if value == "" {
				if r.DefaultAction != "" {
					r.Action = r.DefaultAction
				}
			} else if selection.Valid(value, config.Nodes) {
				r.Action = selection.Action(value)
			} else {
				r.Action = "AUTO"
			}
		}
	}
	apply(config.BaseRules)
	// A temporary global override still wins over ordinary category choices.
	if config.Device.CustomerOverrideAction == "" || config.Device.CustomerOverrideUntil == nil || !config.Device.CustomerOverrideUntil.After(config.ServerTime) {
		apply(config.Rules)
	}
	config.Preferences = prefs
	return config
}

func stateWithLocalPreferences(customer []byte, prefs map[string]string, revision int64) ([]byte, error) {
	var state map[string]json.RawMessage
	if json.Unmarshal(customer, &state) != nil || state == nil {
		return nil, errors.New("invalid customer state")
	}
	state["preferences"], _ = json.Marshal(prefs)
	state["local_revision"], _ = json.Marshal(revision)
	state["preferences_storage"] = json.RawMessage(`"local"`)
	return json.Marshal(state)
}

func (a *agent) saveLocalNodePreference(ctx context.Context, body []byte) localControlResponse {
	if len(body) == 0 || len(body) > 4096 {
		return localControlResponse{Error: "节点设置请求无效。"}
	}
	var input struct {
		Category         string `json:"category"`
		NodeID           string `json:"node_id"`
		ExpectedRevision *int64 `json:"expected_revision,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if !json.Valid(body) || decoder.Decode(&input) != nil {
		return localControlResponse{Error: "节点设置请求无效。"}
	}
	if !a.configMu.TryLock() {
		return localControlResponse{Error: "设备正在应用其他配置，请稍后重试；本次尚未保存。"}
	}
	defer a.configMu.Unlock()
	snapshot, err := a.loadAppliedSnapshot()
	if err != nil {
		return localControlResponse{Error: "本机尚无已验证的规则和节点，不能保存分流设置。"}
	}
	if input.ExpectedRevision != nil && *input.ExpectedRevision != snapshot.LocalRevision {
		return localControlResponse{Error: "本地设置已变化，请刷新后重试。"}
	}
	var customer struct {
		Categories []string `json:"categories"`
	}
	if json.Unmarshal(snapshot.Customer, &customer) != nil {
		return localControlResponse{Error: "本机规则缓存无效。"}
	}
	visible := false
	for _, category := range customer.Categories {
		visible = visible || category == input.Category
	}
	if !visible || !selection.Valid(input.NodeID, snapshot.Config.Nodes) {
		return localControlResponse{Error: "分类或节点已不可用，请刷新后重新选择。"}
	}
	matched := false
	for _, rule := range snapshot.Config.BaseRules {
		if selectableRule(rule) && rule.Category == input.Category && rule.DefaultAction != "" {
			matched = true
		}
	}
	if !matched {
		return localControlResponse{Error: "此规则快照缺少本地分流信息，请先同步新版管理端规则。"}
	}
	local := make(map[string]string, len(snapshot.LocalPreferences)+1)
	for category, value := range snapshot.LocalPreferences {
		local[category] = value
	}
	local[input.Category] = input.NodeID
	if len(local) > 32 {
		return localControlResponse{Error: "本地分类设置过多。"}
	}
	candidate := overlayLocalPreferences(snapshot.Config, local)
	a.stateMu.RLock()
	enabled := a.localProxyOn
	a.stateMu.RUnlock()
	if enabled && (!a.allowDaeProxy || snapshot.SubscriptionID == "") {
		return localControlResponse{Error: "当前无法确认代理订阅；保留上次设置。"}
	}
	policy := makeDaePolicy(a.server, a.interfaceName, candidate, false)
	policy.TCPCheckURL = a.localCheckTarget()
	policy.Rules = localDaeRules(candidate, enabled)
	policy.SubscriptionPresent = snapshot.SubscriptionID != ""
	policy.ProxyEnabled = enabled && snapshot.SubscriptionID != ""
	if candidate.Device.CustomerOverrideAction == "DIRECT" && candidate.Device.CustomerOverrideUntil != nil && candidate.Device.CustomerOverrideUntil.After(time.Now().UTC()) {
		policy.ProxyEnabled = false
	}
	customerState, err := stateWithLocalPreferences(snapshot.Customer, candidate.Preferences, snapshot.LocalRevision+1)
	if err != nil {
		return localControlResponse{Error: "本地设置准备失败，未保存。"}
	}
	applyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 105*time.Second)
	defer cancel()
	result, applyErr := a.daeApplier.Apply(applyCtx, false, nil, &policy)
	if !daePolicyConfirmed(policy.ProxyEnabled, result, applyErr) {
		return localControlResponse{Error: "DAE 未确认新设置，未保存；继续保留上一版。"}
	}
	if err := a.saveSnapshotWithPreferences(candidate, customerState, snapshot.SubscriptionID, local, snapshot.LocalRevision+1); err != nil {
		rollback, ok := a.daeApplier.(interface {
			Rollback(context.Context, string) error
		})
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
		defer cancelRollback()
		if !ok || result.RollbackToken == "" || rollback.Rollback(rollbackCtx, result.RollbackToken) != nil {
			a.stateMu.Lock()
			a.policyReady = false
			a.stateMu.Unlock()
			return localControlResponse{Error: "本地保存失败，配置回退未确认；请检查设备状态。"}
		}
		return localControlResponse{Error: "本地保存失败，已回退到上一版。"}
	}
	encoded, _ := json.Marshal(policy)
	a.daePolicyHash = fmt.Sprintf("%x", sha256.Sum256(encoded))
	a.stateMu.Lock()
	a.proxyApplied, a.policyReady = policy.ProxyEnabled, true
	if policy.ProxyEnabled {
		a.daeStatus, a.daeNodeCount = "ok", result.NodeCount
	}
	a.stateMu.Unlock()
	data, _ := json.Marshal(map[string]any{"ok": true, "validated": true, "applied": policy.ProxyEnabled, "storage": "local", "local_revision": snapshot.LocalRevision + 1, "preferences": candidate.Preferences})
	return localControlResponse{Data: data}
}
