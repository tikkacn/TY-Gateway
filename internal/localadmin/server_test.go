package localadmin

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"tygateway/internal/recovery"
)

func testServer(t *testing.T, withRecovery bool) *Server {
	t.Helper()
	cfg := Config{StateDir: t.TempDir(), DeviceCode: "AA:BB:CC:DD:EE:01", InterfaceName: "not-present", Now: time.Now}
	if withRecovery {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cfg.RecoveryKeyID = "test-v1"
		cfg.RecoveryPublicKey = publicKey
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func call(t *testing.T, s *Server, method, path, body string, cookie *http.Cookie, remote string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://feiliu.local:8088"+path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Host = "feiliu.local:8088"
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "http://feiliu.local:8088")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	return response
}

func TestSetupLoginAndLocalSession(t *testing.T) {
	s := testServer(t, false)
	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, "10.23.43.50:5000")
	if setup.Code != http.StatusNoContent {
		t.Fatalf("setup status=%d body=%s", setup.Code, setup.Body.String())
	}
	cookie := setup.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("session cookie missing HttpOnly or SameSite=Strict")
	}
	state := call(t, s, http.MethodGet, "/api/state", "", cookie, "10.23.43.50:5000")
	if state.Code != http.StatusOK || !strings.Contains(state.Body.String(), `"network_controls":"draft_only"`) {
		t.Fatalf("authenticated state status=%d body=%s", state.Code, state.Body.String())
	}
	unauthorized := call(t, s, http.MethodGet, "/api/state", "", nil, "10.23.43.50:5000")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated state status=%d", unauthorized.Code)
	}
	relogin := call(t, s, http.MethodPost, "/api/login", `{"password":"correct horse battery staple"}`, nil, "10.23.43.50:5000")
	if relogin.Code != http.StatusNoContent {
		t.Fatalf("login status=%d body=%s", relogin.Code, relogin.Body.String())
	}
	loginCookie := relogin.Result().Cookies()[0]
	change := call(t, s, http.MethodPost, "/api/password", `{"current_password":"correct horse battery staple","new_password":"new password chosen by owner"}`, loginCookie, "10.23.43.50:5000")
	if change.Code != http.StatusNoContent {
		t.Fatalf("password change status=%d body=%s", change.Code, change.Body.String())
	}
	oldSession := call(t, s, http.MethodGet, "/api/state", "", loginCookie, "10.23.43.50:5000")
	if oldSession.Code != http.StatusUnauthorized {
		t.Fatalf("old session survived password change: status=%d", oldSession.Code)
	}
	newLogin := call(t, s, http.MethodPost, "/api/login", `{"password":"new password chosen by owner"}`, nil, "10.23.43.50:5000")
	if newLogin.Code != http.StatusNoContent {
		t.Fatalf("new password login status=%d body=%s", newLogin.Code, newLogin.Body.String())
	}
}

func TestNetworkSettingsAreSavedOnlyAsInactiveDraft(t *testing.T) {
	s := testServer(t, false)
	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, "10.23.43.50:5000")
	cookie := setup.Result().Cookies()[0]
	body := `{"plan":{"address_cidr":"10.23.42.211/24","gateway":"10.23.42.1","dhcp_enabled":false,"pool_start":"","pool_end":"","dns_mode":"custom","dns_servers":["1.1.1.1"]},"dns_enabled":false,"reservations":[{"name":"Living room TV","mac":"02:11:22:33:44:55","ip":"10.23.42.20"}]}`
	saved := call(t, s, http.MethodPut, "/api/network/settings", body, cookie, "10.23.43.50:5000")
	if saved.Code != http.StatusOK || !strings.Contains(saved.Body.String(), `"applied":false`) || !strings.Contains(saved.Body.String(), `"dhcp_active":false`) || !strings.Contains(saved.Body.String(), `"lan_dns_active":false`) {
		t.Fatalf("network preset must save while keeping services off: status=%d body=%s", saved.Code, saved.Body.String())
	}
	get := call(t, s, http.MethodGet, "/api/network/settings", "", cookie, "10.23.43.50:5000")
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"mac":"021122334455"`) || !strings.Contains(get.Body.String(), `"apply_available":false`) {
		t.Fatalf("network preset was not persisted safely: status=%d body=%s", get.Code, get.Body.String())
	}
	info, err := os.Stat(s.cfg.StateDir + string(os.PathSeparator) + networkSettingsFile)
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("network preset permissions must be 0600: info=%v err=%v", info, err)
	}
}

func TestNetworkPreviewRequiresSessionAndDoesNotApply(t *testing.T) {
	s := testServer(t, false)
	unauthorized := call(t, s, http.MethodPost, "/api/network/preview", `{"address_cidr":"10.23.42.211/24","gateway":"10.23.42.1","dhcp_enabled":true,"pool_start":"10.23.42.100","pool_end":"10.23.42.200","dns_mode":"router"}`, nil, "10.23.43.50:5000")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated preview status=%d", unauthorized.Code)
	}
	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, "10.23.43.50:5000")
	cookie := setup.Result().Cookies()[0]
	before, err := os.ReadDir(s.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	preview := call(t, s, http.MethodPost, "/api/network/preview", `{"address_cidr":"10.23.42.211/24","gateway":"10.23.42.1","dhcp_enabled":true,"pool_start":"10.23.42.100","pool_end":"10.23.42.200","dns_mode":"router"}`, cookie, "10.23.43.50:5000")
	if preview.Code != http.StatusOK || !strings.Contains(preview.Body.String(), `"apply_enabled":false`) {
		t.Fatalf("preview should validate only and never apply: status=%d body=%s", preview.Code, preview.Body.String())
	}
	if !strings.Contains(preview.Body.String(), "不会更改网络") {
		t.Fatalf("preview response missing no-change warning: %s", preview.Body.String())
	}
	after, err := os.ReadDir(s.cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) || len(after) != 1 || after[0].Name() != "local-admin.json" {
		t.Fatalf("preview unexpectedly persisted network state: before=%v after=%v", before, after)
	}
}

func TestRejectsRemotePeersAndForeignOrigin(t *testing.T) {
	s := testServer(t, false)
	remote := call(t, s, http.MethodGet, "/api/status", "", nil, "203.0.113.8:1234")
	if remote.Code != http.StatusForbidden {
		t.Fatalf("public peer status=%d", remote.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "http://feiliu.local:8088/api/setup", strings.NewReader(`{"password":"correct horse battery staple"}`))
	req.RemoteAddr = "10.23.43.50:5000"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://evil.example")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, req)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign origin status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestOfflineRecoveryIsDeviceAndChallengeBoundAndOneTime(t *testing.T) {
	stateDir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{StateDir: stateDir, DeviceCode: "AABBCCDDEE01", InterfaceName: "not-present", RecoveryKeyID: "test-v1", RecoveryPublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	challengeResponse := call(t, s, http.MethodPost, "/api/recovery/challenge", `{}`, nil, "10.23.43.50:5000")
	if challengeResponse.Code != http.StatusOK {
		t.Fatalf("challenge status=%d body=%s", challengeResponse.Code, challengeResponse.Body.String())
	}
	var challenge struct {
		DeviceCode string `json:"device_code"`
		Challenge  string `json:"challenge"`
	}
	if err := json.Unmarshal(challengeResponse.Body.Bytes(), &challenge); err != nil {
		t.Fatal(err)
	}
	ticket, _, err := recovery.Sign(privateKey, "test-v1", challenge.DeviceCode, challenge.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	resetBody := `{"challenge":"` + challenge.Challenge + `","authorization":"` + ticket + `","new_password":"new safe password 2026"}`
	reset := call(t, s, http.MethodPost, "/api/recovery/reset", resetBody, nil, "10.23.43.50:5000")
	if reset.Code != http.StatusNoContent {
		t.Fatalf("reset status=%d body=%s", reset.Code, reset.Body.String())
	}
	replay := call(t, s, http.MethodPost, "/api/recovery/reset", resetBody, nil, "10.23.43.50:5000")
	if replay.Code != http.StatusUnauthorized {
		t.Fatalf("replayed ticket status=%d body=%s", replay.Code, replay.Body.String())
	}
	login := call(t, s, http.MethodPost, "/api/login", `{"password":"new safe password 2026"}`, nil, "10.23.43.50:5000")
	if login.Code != http.StatusNoContent {
		t.Fatalf("login with recovered password status=%d body=%s", login.Code, login.Body.String())
	}
}
