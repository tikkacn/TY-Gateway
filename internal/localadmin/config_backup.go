package localadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/rules"
	"tygateway/internal/selection"
)

const maxConfigBackupBytes = 256 << 10

// A backup is bound to one device and contains only customer-owned settings.
// It is not an agent-state archive and never contains subscription/FRP secrets.
type customerConfigBackup struct {
	Format               string                      `json:"format"`
	DeviceCode           string                      `json:"device_code"`
	ExportedAt           time.Time                   `json:"exported_at"`
	NetworkDraft         *NetworkSettings            `json:"network_draft,omitempty"`
	Rules                []model.CustomerSettingRule `json:"rules"`
	Preferences          map[string]string           `json:"preferences"`
	ProxyEnabledAtExport bool                        `json:"proxy_enabled_at_export"`
}

type backupCustomerState struct {
	Device      model.CustomerDevice `json:"device"`
	Rules       []model.Rule         `json:"rules"`
	Nodes       []model.CustomerNode `json:"nodes"`
	Categories  []string             `json:"categories"`
	Preferences map[string]string    `json:"preferences"`
}

func (s *Server) backupState(ctx context.Context) (backupCustomerState, error) {
	data, err := s.customerCall(ctx, http.MethodGet, "/me", nil)
	if err != nil {
		return backupCustomerState{}, err
	}
	var state backupCustomerState
	if json.Unmarshal(data, &state) != nil || state.Device.Serial == "" || state.Device.Serial != s.deviceCode() || state.Device.ConfigVersion < 1 || state.Rules == nil || state.Nodes == nil {
		return backupCustomerState{}, errors.New("本机规则快照与设备身份不一致，请先完成同步。")
	}
	return state, nil
}

func (s *Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	state, err := s.backupState(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	proxy, err := s.proxyCall("status", nil)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "无法读取本机代理开关，未生成不完整的备份。"})
		return
	}
	s.networkMu.Lock()
	var draft *NetworkSettings
	if s.network.UpdatedAt != nil {
		copy := s.network
		copy.Plan.DNSServers = append([]string(nil), copy.Plan.DNSServers...)
		copy.Reservations = append([]NetworkReservation(nil), copy.Reservations...)
		draft = &copy
	}
	s.networkMu.Unlock()
	backup := customerConfigBackup{Format: "ty-gateway-customer-config-v1", DeviceCode: state.Device.Serial, ExportedAt: s.cfg.Now().UTC(), NetworkDraft: draft, Rules: []model.CustomerSettingRule{}, Preferences: map[string]string{}, ProxyEnabledAtExport: proxy.Enabled}
	for _, rule := range state.Rules {
		if rule.Source != "customer" || rule.SourceType != "user" {
			continue
		}
		backup.Rules = append(backup.Rules, model.CustomerSettingRule{MatchType: rule.MatchType, MatchValue: rule.MatchValue, Action: rule.Action})
	}
	for category, value := range state.Preferences {
		backup.Preferences[category] = value
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=ty-gateway-%s-config.json", state.Device.Serial))
	writeJSON(w, http.StatusOK, backup)
}

func decodeConfigBackup(w http.ResponseWriter, r *http.Request) (customerConfigBackup, bool) {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, apiError{Error: "请上传 JSON 配置文件。"})
		return customerConfigBackup{}, false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxConfigBackupBytes))
	decoder.DisallowUnknownFields()
	var backup customerConfigBackup
	if decoder.Decode(&backup) != nil || decoder.Decode(new(any)) != io.EOF {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "配置文件格式错误或超过 256 KB。"})
		return customerConfigBackup{}, false
	}
	return backup, true
}

func (s *Server) checkedBackup(ctx context.Context, backup customerConfigBackup) (backupCustomerState, *NetworkSettings, error) {
	state, err := s.backupState(ctx)
	if err != nil {
		return state, nil, err
	}
	if backup.Format != "ty-gateway-customer-config-v1" || backup.DeviceCode == "" || backup.DeviceCode != state.Device.Serial || backup.ExportedAt.IsZero() || backup.Rules == nil || backup.Preferences == nil || len(backup.Rules) > 200 || len(backup.Preferences) > 32 {
		return state, nil, errors.New("配置格式或设备码不匹配；只能恢复这台设备导出的完整备份。")
	}
	var draft *NetworkSettings
	if backup.NetworkDraft != nil {
		validated, err := validateNetworkSettings(*backup.NetworkDraft)
		if err != nil {
			return state, nil, err
		}
		validated.UpdatedAt = nil
		draft = &validated
	}
	nodes := make([]model.Node, 0, len(state.Nodes))
	for _, node := range state.Nodes {
		nodes = append(nodes, model.Node{ID: node.ID, Name: node.Name, Group: node.Group})
	}
	seen := map[string]bool{}
	for _, rule := range backup.Rules {
		if rule.MatchType == "domain" || rule.MatchType == "domain_suffix" {
			if !validBackupDomain(rule.MatchValue) || rule.MatchValue != strings.ToLower(rule.MatchValue) {
				return state, nil, errors.New("备份包含无效域名规则。")
			}
		} else if rule.MatchType == "ip" || rule.MatchType == "cidr" || rule.MatchType == "ip_cidr" {
			value, err := rules.NormalizeIPMatchValue(rule.MatchValue)
			if err != nil || value != rule.MatchValue {
				return state, nil, errors.New("备份包含无效 IP 规则。")
			}
		} else {
			return state, nil, errors.New("备份包含不支持的规则类型。")
		}
		if !validBackupAction(rule.Action, nodes) {
			return state, nil, errors.New("备份包含已不可用的规则节点或动作。")
		}
		key := rule.MatchType + "\x00" + rule.MatchValue
		if seen[key] {
			return state, nil, errors.New("备份包含重复规则。")
		}
		seen[key] = true
	}
	categorySet := map[string]bool{}
	for _, category := range state.Categories {
		categorySet[category] = true
	}
	if len(state.Categories) == 0 && state.Device.Profile == "gfw_precise" {
		categorySet["GFW"] = true
	}
	for category, value := range backup.Preferences {
		if !categorySet[category] || value == "" || len(value) > 64 || !selection.Valid(value, nodes) {
			return state, nil, errors.New("备份包含当前方案无法使用的分类或节点。")
		}
	}
	return state, draft, nil
}

func validBackupDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validBackupAction(action string, nodes []model.Node) bool {
	switch action {
	case "DIRECT", "PROXY", "AUTO", "BLOCK":
		return true
	}
	if len(action) > 64 {
		return false
	}
	for _, node := range nodes {
		if action == "NODE:"+node.ID || node.Group != "" && action == "GROUP:"+node.Group {
			return true
		}
	}
	return false
}

func backupPreview(backup customerConfigBackup, draft *NetworkSettings) map[string]any {
	address := "保持当前网络预设"
	if draft != nil {
		address = draft.Plan.AddressCIDR
	}
	return map[string]any{"device_code": backup.DeviceCode, "rules": len(backup.Rules), "preferences": len(backup.Preferences), "network_draft": address, "network_will_apply": false, "proxy_will_enable": false, "notice": "导入后仅保存网络预设，不切换 IP/DHCP/DNS；代理开关不会因备份自动开启。"}
}

func (s *Server) previewConfigImport(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) || !s.allow(r, 12) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "请求被拒绝或操作过于频繁。"})
		return
	}
	backup, ok := decodeConfigBackup(w, r)
	if !ok {
		return
	}
	_, draft, err := s.checkedBackup(r.Context(), backup)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, backupPreview(backup, draft))
}

func (s *Server) importConfig(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) || !s.allow(r, 12) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "请求被拒绝或操作过于频繁。"})
		return
	}
	backup, ok := decodeConfigBackup(w, r)
	if !ok {
		return
	}
	state, draft, err := s.checkedBackup(r.Context(), backup)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: err.Error()})
		return
	}
	if _, err := s.replaceCloudCustomerSettings(r.Context(), state.Device.ConfigVersion, backup.Rules, backup.Preferences); err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	if draft != nil {
		now := s.cfg.Now().UTC()
		draft.UpdatedAt = &now
		s.networkMu.Lock()
		err = saveNetworkSettings(s.cfg.StateDir, *draft)
		if err == nil {
			s.network = *draft
		}
		s.networkMu.Unlock()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiError{Error: "云端用户规则已恢复，但本地网络预设保存失败；请先导出当前配置核对。"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "network_applied": false, "proxy_automatically_changed": false, "message": "用户规则已恢复；网络预设未实际应用，代理开关未因备份自动改变。"})
}

func (s *Server) resetCustomerConfig(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) || !s.allow(r, 12) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "请求被拒绝或操作过于频繁。"})
		return
	}
	var input struct {
		Confirm string `json:"confirm"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if input.Confirm != "RESET_CUSTOMER_SETTINGS" {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请确认重置用户设置。"})
		return
	}
	state, err := s.backupState(r.Context())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	off := false
	proxy, err := s.proxyCall("set", &off)
	if err != nil || proxy.Enabled || proxy.DaemonActive || proxy.Error != "" {
		writeJSON(w, http.StatusConflict, apiError{Error: "无法确认代理已关闭，因此未清除用户设置。"})
		return
	}
	if _, err := s.replaceCloudCustomerSettings(r.Context(), state.Device.ConfigVersion, []model.CustomerSettingRule{}, map[string]string{}); err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "代理已关闭，但云端用户设置未确认清除：" + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proxy_enabled": false, "message": "已关闭代理并清除用户自定义规则、节点偏好和临时模式；网络入口、本地密码、设备注册和管理员规则均保留。"})
}

func (s *Server) replaceCloudCustomerSettings(ctx context.Context, version int64, customerRules []model.CustomerSettingRule, prefs map[string]string) ([]byte, error) {
	request, err := json.Marshal(map[string]any{"expected_version": version, "rules": customerRules, "preferences": prefs})
	if err != nil || len(request) > maxConfigBackupBytes {
		return nil, errors.New("客户配置过大，未发送到云端。")
	}
	data, err := s.customerCall(ctx, http.MethodPost, "/settings", request)
	if err != nil {
		return nil, err
	}
	var confirmation struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(data, &confirmation) != nil || !confirmation.OK {
		return nil, errors.New("云端未确认客户配置。")
	}
	return data, nil
}
