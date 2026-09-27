package localadmin

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tygateway/internal/model"
)

func TestConfigBackupPreviewImportAndResetStayScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable on test host: %v", err)
	}
	defer listener.Close()
	requests := make(chan localControlRequestForTest, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var request localControlRequestForTest
			_ = json.NewDecoder(conn).Decode(&request)
			requests <- request
			switch request.Action {
			case "customer":
				if request.Method == "GET" {
					_, _ = conn.Write([]byte(`{"data":{"device":{"serial":"AABBCCDDEE01","config_version":3},"rules":[],"nodes":[],"categories":["AI"],"preferences":{},"private_key":"must-not-export"}}` + "\n"))
				} else {
					_, _ = conn.Write([]byte(`{"data":{"ok":true,"config_version":4}}` + "\n"))
				}
			default:
				_, _ = conn.Write([]byte(`{"enabled":false,"daemon_active":false}` + "\n"))
			}
			_ = conn.Close()
		}
	}()
	s := testServer(t, false)
	s.cfg.AgentSocket = path
	s.cfg.NetworkSocket = filepath.Join(t.TempDir(), "no-network-helper.sock")
	remote := "10.23.43.50:5000"
	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, remote)
	cookie := setup.Result().Cookies()[0]
	unauthorized := call(t, s, http.MethodGet, "/api/config/export", "", nil, remote)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("export without session=%d", unauthorized.Code)
	}
	draft := NetworkSettings{Plan: NetworkPlanInput{AddressCIDR: "10.23.42.212/24", Gateway: "10.23.42.1", DNSMode: "router"}, Reservations: []NetworkReservation{}}
	backup := customerConfigBackup{Format: "ty-gateway-customer-config-v1", DeviceCode: "AABBCCDDEE01", ExportedAt: time.Now().UTC(), NetworkDraft: &draft, Rules: []model.CustomerSettingRule{{MatchType: "domain_suffix", MatchValue: "example.org", Action: "DIRECT"}}, Preferences: map[string]string{}}
	data, _ := json.Marshal(backup)
	wrong := strings.Replace(string(data), "AABBCCDDEE01", "AABBCCDDEE02", 1)
	rejected := call(t, s, http.MethodPost, "/api/config/preview", wrong, cookie, remote)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("other-device backup accepted: %d %s", rejected.Code, rejected.Body.String())
	}
	preview := call(t, s, http.MethodPost, "/api/config/preview", string(data), cookie, remote)
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"network_will_apply":false`) {
		t.Fatalf("preview status=%d %s", preview.Code, preview.Body.String())
	}
	if _, err := os.Stat(filepath.Join(s.cfg.StateDir, networkSettingsFile)); !os.IsNotExist(err) {
		t.Fatalf("preview unexpectedly wrote network draft: %v", err)
	}
	imported := call(t, s, http.MethodPost, "/api/config/import", string(data), cookie, remote)
	if imported.Code != http.StatusOK || !strings.Contains(imported.Body.String(), `"network_applied":false`) {
		t.Fatalf("import status=%d %s", imported.Code, imported.Body.String())
	}
	settings, err := loadNetworkSettings(s.cfg.StateDir)
	if err != nil || settings.Plan.AddressCIDR != draft.Plan.AddressCIDR {
		t.Fatalf("network draft was not safely saved: %#v %v", settings, err)
	}
	var posted bool
	for len(requests) > 0 {
		request := <-requests
		if request.Method == "POST" && request.Path == "/settings" {
			posted = true
		}
	}
	if !posted {
		t.Fatal("import did not request atomic customer settings replacement")
	}
	exported := call(t, s, http.MethodGet, "/api/config/export", "", cookie, remote)
	if exported.Code != http.StatusOK || strings.Contains(exported.Body.String(), "must-not-export") || strings.Contains(exported.Body.String(), "subscription") || !strings.Contains(exported.Body.String(), `"device_code":"AABBCCDDEE01"`) {
		t.Fatalf("export leaked or omitted fields: %d %s", exported.Code, exported.Body.String())
	}
	badReset := call(t, s, http.MethodPost, "/api/config/reset", `{"confirm":"no"}`, cookie, remote)
	if badReset.Code != http.StatusBadRequest {
		t.Fatalf("reset without explicit confirmation=%d", badReset.Code)
	}
	reset := call(t, s, http.MethodPost, "/api/config/reset", `{"confirm":"RESET_CUSTOMER_SETTINGS"}`, cookie, remote)
	if reset.Code != http.StatusOK || !strings.Contains(reset.Body.String(), `"proxy_enabled":false`) {
		t.Fatalf("reset status=%d %s", reset.Code, reset.Body.String())
	}
	settings, err = loadNetworkSettings(s.cfg.StateDir)
	if err != nil || settings.Plan.AddressCIDR != draft.Plan.AddressCIDR || !s.hasPassword {
		t.Fatalf("reset changed network entry or password: %#v %v", settings, err)
	}
}

type localControlRequestForTest struct {
	Action string `json:"action"`
	Method string `json:"method"`
	Path   string `json:"path"`
}
