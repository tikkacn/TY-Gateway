package localadmin

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// Only this narrow protocol crosses into the privileged network helper.
// No caller-controlled command, path, interface, or service name is accepted.
type networkApplyResult struct {
	Phase            string           `json:"phase"`
	TargetIP         string           `json:"target_ip,omitempty"`
	OldIP            string           `json:"old_ip,omitempty"`
	Deadline         int64            `json:"deadline,omitempty"`
	Message          string           `json:"message,omitempty"`
	Error            string           `json:"error,omitempty"`
	FailureStage     string           `json:"failure_stage,omitempty"`
	FailureCode      string           `json:"failure_code,omitempty"`
	DHCPActive       bool             `json:"dhcp_active"`
	DNSActive        bool             `json:"lan_dns_active"`
	ServiceState     string           `json:"service_state,omitempty"`
	ReservationCount int              `json:"reservation_count"`
	AppliedSettings  *NetworkSettings `json:"applied_settings,omitempty"`
}

func (s *Server) networkCall(request map[string]string) (networkApplyResult, error) {
	var result networkApplyResult
	if s.cfg.NetworkSocket == "" {
		return result, errors.New("本机尚未配置安全地址切换服务；仅保存了预设。")
	}
	c, err := net.DialTimeout("unix", s.cfg.NetworkSocket, 3*time.Second)
	if err != nil {
		return result, errors.New("地址切换服务不可用，未确认应用；请联系管理员。")
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(95 * time.Second))
	if err = json.NewEncoder(c).Encode(request); err == nil {
		err = json.NewDecoder(io.LimitReader(c, 65536)).Decode(&result)
	}
	if err != nil {
		return result, errors.New("地址操作响应中断；请检查新地址，未确认的变更将在约三分钟后恢复。")
	}
	if result.Error != "" {
		return result, errors.New(result.Error)
	}
	return result, nil
}

func (s *Server) lanServiceStatus(w http.ResponseWriter, r *http.Request) {
	result, err := s.networkCall(map[string]string{"action": "lan_status"})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) applyLANServices(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 10) {
		writeRateLimit(w)
		return
	}
	var request struct {
		Settings      NetworkSettings `json:"settings"`
		RouterDHCPOff bool            `json:"router_dhcp_off"`
	}
	if !decodeBody(w, r, &request) {
		return
	}
	s.networkMu.Lock()
	defer s.networkMu.Unlock()
	expected, _ := json.Marshal(request.Settings)
	current, _ := json.Marshal(s.network)
	if string(expected) != string(current) || s.network.UpdatedAt == nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "设置已变化，请重新保存后应用。"})
		return
	}
	confirmed := "false"
	if request.RouterDHCPOff {
		confirmed = "true"
	}
	result, err := s.networkCall(map[string]string{"action": "lan_apply", "settings": string(current), "router_dhcp_off": confirmed})
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) networkApplyStatus(w http.ResponseWriter, r *http.Request) {
	result, err := s.networkCall(map[string]string{"action": "status"})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) applyNetworkAddress(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 10) {
		writeRateLimit(w)
		return
	}
	// Revalidate the expected saved plan to reject a stale form / simultaneous edit.
	var expected NetworkPlanInput
	if !decodeBody(w, r, &expected) {
		return
	}
	s.networkMu.Lock()
	defer s.networkMu.Unlock()
	if s.network.UpdatedAt == nil || expected.AddressCIDR != s.network.Plan.AddressCIDR || expected.Gateway != s.network.Plan.Gateway {
		writeJSON(w, http.StatusConflict, apiError{Error: "预设已变化，请刷新页面后重新保存。"})
		return
	}
	result, err := s.networkCall(map[string]string{"action": "apply", "address_cidr": expected.AddressCIDR, "gateway": expected.Gateway})
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	s.mu.Lock()
	s.revokeSessionsLocked()
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) confirmNetworkAddress(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 10) {
		writeRateLimit(w)
		return
	}
	// Host and forwarding headers are not proof of reaching the new address.
	addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		writeJSON(w, http.StatusForbidden, apiError{Error: "无法确认访问地址。"})
		return
	}
	ip, _, err := net.SplitHostPort(addr.String())
	if err != nil || net.ParseIP(ip).To4() == nil {
		writeJSON(w, http.StatusForbidden, apiError{Error: "请通过新的 IPv4 地址登录。"})
		return
	}
	result, err := s.networkCall(map[string]string{"action": "confirm", "local_ip": net.ParseIP(ip).To4().String()})
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}
