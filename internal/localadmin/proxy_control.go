package localadmin

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

type proxyControlState struct {
	Initializing bool   `json:"initializing,omitempty"`
	Enabled      bool   `json:"enabled"`
	Applied      bool   `json:"applied"`
	RulesProfile string `json:"rules_profile,omitempty"`
	RulesVersion string `json:"rules_version,omitempty"`
	Ready        bool   `json:"ready"`
	Subscription bool   `json:"subscription_available"`
	NodeCount    int    `json:"node_count"`
	DaemonActive bool   `json:"daemon_active"`
	Error        string `json:"error,omitempty"`
}

func (s *Server) proxyCall(action string, enabled *bool) (proxyControlState, error) {
	var state proxyControlState
	if s.cfg.AgentSocket == "" {
		return state, errors.New("本机代理控制服务尚未安装或升级。")
	}
	conn, err := net.DialTimeout("unix", s.cfg.AgentSocket, 3*time.Second)
	if err != nil {
		return state, errors.New("本机代理控制服务暂不可用，请稍后刷新页面。")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(125 * time.Second))
	request := struct {
		Action  string `json:"action"`
		Enabled *bool  `json:"enabled,omitempty"`
	}{Action: action, Enabled: enabled}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return state, errors.New("无法联系本机代理控制服务。")
	}
	if err := json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&state); err != nil {
		return state, errors.New("本机代理控制服务响应无效。")
	}
	return state, nil
}

func (s *Server) getProxyStatus(w http.ResponseWriter, r *http.Request) {
	state, err := s.proxyCall("status", nil)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) setProxyStatus(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 6) {
		writeRateLimit(w)
		return
	}
	var request struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeBody(w, r, &request) {
		return
	}
	if request.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "请明确选择开启或关闭。"})
		return
	}
	state, err := s.proxyCall("set", request.Enabled)
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, state)
}
