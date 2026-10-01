package frpauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCredentialAndPluginAuthorization(t *testing.T) {
	const id = "device-01"
	credential, err := Credential(strings.Repeat("a", 64), id, 22001)
	if err != nil || len(credential) != 64 {
		t.Fatalf("credential: %v", err)
	}
	other, _ := Credential(strings.Repeat("a", 64), id, 22002)
	if credential == other {
		t.Fatal("credential must be port-specific")
	}
	roster := Roster{GeneratedAt: time.Now().UTC(), Entries: []Entry{{DeviceID: id, Port: 22001, CredentialHash: CredentialHash(credential)}}}
	p := NewPlugin(time.Hour, 22001, 22099)
	if err := p.SetRoster(roster); err != nil {
		t.Fatal(err)
	}
	request := func(op, content string) (*httptest.ResponseRecorder, bool) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"content": json.RawMessage(content)})
		r := httptest.NewRequest(http.MethodPost, "/handler?version=0.1.0&op="+op, strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("plugin status %d", w.Code)
		}
		return w, strings.Contains(w.Body.String(), `"reject":false`)
	}
	login := `{"user":"device-01","timestamp":1770000000,"version":"0.71.0","privilege_key":"signed-oidc-jwt","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}}`
	user := `{"user":{"user":"device-01","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}}}`
	workConn := `{"user":{"user":"device-01","run_id":"run-01","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}},"run_id":"run-01"}`
	loginResponse, loginAllowed := request("Login", login)
	if !loginAllowed {
		t.Fatal("correct device credential rejected")
	}
	var reply struct {
		Unchange bool            `json:"unchange"`
		Content  json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(loginResponse.Body.Bytes(), &reply); err != nil || !reply.Unchange || len(reply.Content) != 0 {
		t.Fatalf("Login OIDC credential was not passed unchanged to FRPS native verification: response=%s err=%v", loginResponse.Body.String(), err)
	}
	if _, ok := request("Login", strings.Replace(login, credential, strings.Repeat("b", 64), 1)); ok {
		t.Fatal("Login with an invalid per-device credential was accepted")
	}
	if _, ok := request("Ping", user); !ok {
		t.Fatal("correct device credential rejected for ping")
	}
	if _, ok := request("NewWorkConn", workConn); !ok {
		t.Fatal("correct device credential rejected")
	}
	validProxy := `{"user":{"user":"device-01","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}},"proxy_name":"device-01.ssh-rescue","proxy_type":"tcp","remote_port":22001}`
	if _, ok := request("NewProxy", validProxy); !ok {
		t.Fatal("correct SSH mapping rejected")
	}
	for _, bad := range []string{
		strings.Replace(validProxy, `"remote_port":22001`, `"remote_port":22002`, 1),
		strings.Replace(validProxy, `"proxy_type":"tcp"`, `"proxy_type":"http"`, 1),
		strings.Replace(validProxy, `"proxy_name":"device-01.ssh-rescue"`, `"proxy_name":"admin"`, 1),
		strings.Replace(validProxy, `"proxy_name":"device-01.ssh-rescue"`, `"proxy_name":"device-01.device-01.ssh-rescue"`, 1),
		strings.Replace(validProxy, `"remote_port":22001`, `"remote_port":22001,"group":"shared"`, 1),
		strings.Replace(validProxy, credential, strings.Repeat("b", 64), 1),
		strings.Replace(validProxy, `"device_id":"device-01"`, `"device_id":"device-02"`, 1),
	} {
		if _, ok := request("NewProxy", bad); ok {
			t.Fatalf("unauthorized proxy accepted: %s", bad)
		}
	}
	if _, ok := request("UnknownOp", user); ok {
		t.Fatal("unknown operation accepted")
	}
	if _, ok := request("Login", `{}`); ok {
		t.Fatal("unknown operation or empty login accepted")
	}
	if _, ok := request("NewWorkConn", strings.Replace(workConn, `"run_id":"run-01"}`, `"run_id":"other"}`, 1)); ok {
		t.Fatal("work connection with mismatched run ID accepted")
	}
	if err := p.SetRoster(Roster{GeneratedAt: time.Now().Add(-2 * time.Hour)}); err == nil {
		t.Fatal("stale roster was accepted")
	}
	if _, ok := request("Login", login); !ok {
		t.Fatal("failed roster update discarded last good state")
	}
	if err := p.SetRoster(Roster{GeneratedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	for op, content := range map[string]string{"Login": login, "Ping": user, "NewWorkConn": workConn, "NewProxy": validProxy,
		"NewUserConn": strings.TrimSuffix(user, "}") + `,"proxy_name":"device-01.ssh-rescue"}`} {
		if _, ok := request(op, content); ok {
			t.Fatalf("revoked device still authorized for %s", op)
		}
	}
}

func TestPluginRequiresFreshRoster(t *testing.T) {
	p := NewPlugin(time.Hour, 22000, 22999)
	if err := p.SetRoster(Roster{GeneratedAt: time.Now().UTC().Add(-2 * time.Hour), Entries: []Entry{{DeviceID: "device-01", Port: 22000, CredentialHash: strings.Repeat("a", 64)}}}); err == nil {
		t.Fatal("stale authorization roster accepted")
	}
	if p.Ready() {
		t.Fatal("plugin became ready without a fresh roster")
	}
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("health check status without fresh roster = %d, want 503", w.Code)
	}
}

func TestPluginReadyWithFreshRosterWithoutServerSharedToken(t *testing.T) {
	p := NewPlugin(time.Hour, 22000, 22999)
	if err := p.SetRoster(Roster{GeneratedAt: time.Now().UTC(), Entries: []Entry{{DeviceID: "device-01", Port: 22000, CredentialHash: strings.Repeat("a", 64)}}}); err != nil {
		t.Fatal(err)
	}
	if !p.Ready() {
		t.Fatal("plugin should be ready from its signed-feed-derived roster; FRP OIDC handles native authentication")
	}
}

func TestRosterRejectsDuplicates(t *testing.T) {
	h := strings.Repeat("a", 64)
	roster := Roster{GeneratedAt: time.Now().UTC(), Entries: []Entry{{DeviceID: "one", Port: 22001, CredentialHash: h}, {DeviceID: "two", Port: 22001, CredentialHash: h}}}
	if roster.Validate(time.Now(), time.Hour, 22001, 22099) == nil {
		t.Fatal("duplicate port accepted")
	}
}
