package localadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"tygateway/internal/ruleseed"
)

type localCustomerResponse struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

func (s *Server) customerMe(w http.ResponseWriter, r *http.Request) {
	data, err := s.customerCall(r.Context(), http.MethodGet, "/me", nil)
	if err != nil {
		// Registration may still be retrying, so the Agent socket need not be
		// available yet. Public seeds are read-only, never a routing-ready claim.
		writeJSON(w, http.StatusOK, map[string]any{"device": map[string]any{}, "rule_packages": ruleseed.Catalog(), "nodes": []any{}, "rules": []any{}, "categories": []string{}, "preferences": map[string]string{}, "initialization_pending": true, "initialization_message": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) customerRules(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/customer")
	if path == "" {
		path = "/me"
	}
	switch path {
	case "/rules", "/rules/delete", "/override", "/node-preference", "/action", "/rule-package", "/speed-test", "/speed-test/settings", "/speed-test/run":
	default:
		writeJSON(w, http.StatusNotFound, apiError{Error: "customer operation not found"})
		return
	}
	s.forwardCustomer(w, r, r.Method, path)
}

func (s *Server) forwardCustomer(w http.ResponseWriter, r *http.Request, method, path string) {
	if method != http.MethodGet {
		if !s.validMutation(r) {
			writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
			return
		}
		if !s.allow(r, 12) {
			writeRateLimit(w)
			return
		}
	}
	body := []byte{}
	if method != http.MethodGet {
		if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, apiError{Error: "application/json required"})
			return
		}
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil || len(body) == 0 || !json.Valid(body) {
			writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
			return
		}
	}
	data, err := s.customerCall(r.Context(), method, path, body)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) customerCall(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if s.cfg.AgentSocket == "" {
		return nil, errors.New("本机 Agent 尚未提供客户配置服务。")
	}
	conn, err := net.DialTimeout("unix", s.cfg.AgentSocket, 3*time.Second)
	if err != nil {
		return nil, errors.New("本机 Agent 暂不可用，请稍后重试。")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(124 * time.Second))
	request := struct {
		Action string          `json:"action"`
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body,omitempty"`
	}{Action: "customer", Method: method, Path: path, Body: body}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, errors.New("无法联系本机 Agent。")
	}
	var response localCustomerResponse
	if err := json.NewDecoder(io.LimitReader(conn, 512<<10)).Decode(&response); err != nil {
		return nil, errors.New("本机 Agent 响应无效。")
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}
	if len(response.Data) == 0 || len(response.Data) > 256<<10 || !json.Valid(response.Data) {
		return nil, errors.New("本机客户配置响应无效。")
	}
	return response.Data, nil
}
