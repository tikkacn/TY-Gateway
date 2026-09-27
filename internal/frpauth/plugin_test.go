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
	request := func(op, content string) bool {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"content": json.RawMessage(content)})
		r := httptest.NewRequest(http.MethodPost, "/handler?version=0.1.0&op="+op, strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		p.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("plugin status %d", w.Code)
		}
		return strings.Contains(w.Body.String(), `"reject":false`)
	}
	login := `{"user":"device-01","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}}`
	user := `{"user":{"user":"device-01","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}}}`
	workConn := `{"user":{"user":"device-01","run_id":"run-01","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}},"run_id":"run-01"}`
	if !request("Login", login) || !request("Ping", user) || !request("NewWorkConn", workConn) {
		t.Fatal("correct device credential rejected")
	}
	validProxy := `{"user":{"user":"device-01","metas":{"device_id":"device-01","rescue_key":"` + credential + `"}},"proxy_name":"device-01.ssh-rescue","proxy_type":"tcp","remote_port":22001}`
	if !request("NewProxy", validProxy) {
		t.Fatal("correct SSH mapping rejected")
	}
	for _, bad := range []string{
		strings.Replace(validProxy, `"remote_port":22001`, `"remote_port":22002`, 1),
		strings.Replace(validProxy, `"proxy_type":"tcp"`, `"proxy_type":"http"`, 1),
		strings.Replace(validProxy, `"proxy_name":"device-01.ssh-rescue"`, `"proxy_name":"admin"`, 1),
		strings.Replace(validProxy, `"remote_port":22001`, `"remote_port":22001,"group":"shared"`, 1),
		strings.Replace(validProxy, credential, strings.Repeat("b", 64), 1),
		strings.Replace(validProxy, `"device_id":"device-01"`, `"device_id":"device-02"`, 1),
	} {
		if request("NewProxy", bad) {
			t.Fatalf("unauthorized proxy accepted: %s", bad)
		}
	}
	if request("UnknownOp", user) || request("Login", `{}`) {
		t.Fatal("unknown operation or empty login accepted")
	}
	if request("NewWorkConn", strings.Replace(workConn, `"run_id":"run-01"}`, `"run_id":"other"}`, 1)) {
		t.Fatal("work connection with mismatched run ID accepted")
	}
	if err := p.SetRoster(Roster{GeneratedAt: time.Now().Add(-2 * time.Hour)}); err == nil {
		t.Fatal("stale roster was accepted")
	}
	if !request("Login", login) {
		t.Fatal("failed roster update discarded last good state")
	}
}

func TestRosterRejectsDuplicates(t *testing.T) {
	h := strings.Repeat("a", 64)
	roster := Roster{GeneratedAt: time.Now().UTC(), Entries: []Entry{{DeviceID: "one", Port: 22001, CredentialHash: h}, {DeviceID: "two", Port: 22001, CredentialHash: h}}}
	if roster.Validate(time.Now(), time.Hour, 22001, 22099) == nil {
		t.Fatal("duplicate port accepted")
	}
}
