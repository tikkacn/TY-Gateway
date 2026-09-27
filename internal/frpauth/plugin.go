package frpauth

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// Plugin implements FRP's server-plugin protocol for an isolated new FRPS
// listener. Every active operation is authorized from global FRPC metadata;
// it is not safe to attach this plugin only to NewProxy.
type Plugin struct {
	mu        sync.RWMutex
	roster    Roster
	maxAge    time.Duration
	portStart int
	portEnd   int
}

func NewPlugin(maxAge time.Duration, portStart, portEnd int) *Plugin {
	return &Plugin{maxAge: maxAge, portStart: portStart, portEnd: portEnd}
}

func (p *Plugin) SetRoster(roster Roster) error {
	if err := roster.Validate(time.Now().UTC(), p.maxAge, p.portStart, p.portEnd); err != nil {
		return err
	}
	p.mu.Lock()
	p.roster = roster
	p.mu.Unlock()
	return nil
}

func (p *Plugin) Ready() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.roster.Validate(time.Now().UTC(), p.maxAge, p.portStart, p.portEnd) == nil
}

type pluginEnvelope struct {
	Content json.RawMessage `json:"content"`
}

type pluginUser struct {
	User  string            `json:"user"`
	Metas map[string]string `json:"metas"`
	RunID string            `json:"run_id"`
}

type loginContent struct {
	User  string            `json:"user"`
	Metas map[string]string `json:"metas"`
}

type operationContent struct {
	User       pluginUser `json:"user"`
	ProxyName  string     `json:"proxy_name"`
	ProxyType  string     `json:"proxy_type"`
	RemotePort int        `json:"remote_port"`
	Group      string     `json:"group"`
	GroupKey   string     `json:"group_key"`
	RunID      string     `json:"run_id"`
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		if !p.Ready() {
			http.Error(w, "roster unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
		return
	}
	if r.URL.Path != "/handler" || r.Method != http.MethodPost || r.URL.Query().Get("version") != "0.1.0" {
		http.NotFound(w, r)
		return
	}
	allow := false
	if r.ContentLength <= 16<<10 {
		var envelope pluginEnvelope
		body, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
		if err == nil && len(body) <= 16<<10 && json.Unmarshal(body, &envelope) == nil {
			allow = p.authorize(r.URL.Query().Get("op"), envelope.Content)
		}
	}
	if !allow {
		// FRPS treats non-200 as plugin failure. Return an explicit reject.
		_, _ = io.WriteString(w, `{"reject":true,"reject_reason":"rescue authorization denied"}`)
		return
	}
	_, _ = io.WriteString(w, `{"reject":false,"unchange":true}`)
}

func (p *Plugin) authorize(op string, raw json.RawMessage) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.roster.Validate(time.Now().UTC(), p.maxAge, p.portStart, p.portEnd) != nil {
		return false
	}
	var id string
	var metas map[string]string
	var operation operationContent
	if op == "Login" {
		var login loginContent
		if json.Unmarshal(raw, &login) != nil {
			return false
		}
		id, metas = login.User, login.Metas
	} else {
		if op != "NewProxy" && op != "Ping" && op != "NewWorkConn" && op != "NewUserConn" && op != "CloseProxy" || json.Unmarshal(raw, &operation) != nil {
			return false
		}
		id, metas = operation.User.User, operation.User.Metas
	}
	if id == "" || metas["device_id"] != id {
		return false
	}
	entry, ok := p.roster.Authorize(id, metas["rescue_key"])
	if !ok {
		return false
	}
	if op == "NewProxy" {
		return operation.ProxyType == "tcp" && operation.RemotePort == entry.Port && operation.ProxyName == id+".ssh-rescue" && operation.Group == "" && operation.GroupKey == ""
	}
	if op == "NewWorkConn" {
		return operation.RunID != "" && operation.RunID == operation.User.RunID
	}
	if op == "NewUserConn" || op == "CloseProxy" {
		return operation.ProxyName == id+".ssh-rescue"
	}
	return true
}
