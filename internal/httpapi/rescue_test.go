package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestAdminRescueOverviewJoinsDeviceIdentityAndNeverContainsSecrets(t *testing.T) {
	st := store.NewMemoryStore()
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:00:01"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRescueSSHPort(context.Background(), d.ID, 22000); err != nil {
		t.Fatal(err)
	}
	sub, err := st.CreateSubscription(context.Background(), "home-plan", "v2board", []byte("ciphertext-only"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpdateIdentity(context.Background(), d.ID, "user-001", "customer@example.test", sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpdateDevice(context.Background(), d.ID, model.DevicePending, "family use", ""); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.FRPS.Host = "frps.example.test"
	unauth := httptest.NewRecorder()
	srv.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "/api/v1/admin/rescue", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated rescue overview status = %d", unauth.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/rescue", nil)
	req.Header.Set("X-TY-Admin-Token", "admin-test")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("rescue overview status = %d: %s", w.Code, w.Body.String())
	}
	var got rescueOverview
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Host != "frps.example.test" || got.ControlPort != 7001 || len(got.Devices) != 1 {
		t.Fatalf("unexpected overview metadata: %+v", got)
	}
	entry := got.Devices[0]
	if entry.ID != d.ID || entry.MAC != d.MAC || entry.Serial != d.Serial || entry.Name != "user-001" || entry.Email != "customer@example.test" || entry.Subscription != "home-plan" {
		t.Fatalf("device identity was not joined correctly: %+v", entry)
	}
	if !entry.PortAssigned || !entry.PortAvailable || entry.RemotePort != 22000 || entry.TunnelStatus != "unverified" {
		t.Fatalf("unexpected rescue mapping state: %+v", entry)
	}
	body := strings.ToLower(w.Body.String())
	for _, forbidden := range []string{"password", "frps.token", "ciphertext-only", "url_ciphertext"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("rescue overview exposed forbidden data %q", forbidden)
		}
	}
}

func TestCustomerCannotReadAdminRescueOverview(t *testing.T) {
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:00:02"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateDevice(context.Background(), d.ID, model.DeviceEnabled, "", ""); err != nil {
		t.Fatal(err)
	}
	_, accessToken, err := st.RotateCustomerAccess(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := json.Marshal(map[string]string{"device_code": d.Serial, "access_token": accessToken})
	login := httptest.NewRecorder()
	srv.ServeHTTP(login, httptest.NewRequest(http.MethodPost, "/api/v1/customer/login", strings.NewReader(string(loginBody))))
	if login.Code != http.StatusOK {
		t.Fatalf("customer login status = %d", login.Code)
	}
	var session struct {
		Token string `json:"session_token"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &session); err != nil || session.Token == "" {
		t.Fatal("customer session was not created")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/rescue", nil)
	req.Header.Set("Authorization", "Bearer "+session.Token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("customer session accessed admin rescue overview: %d", w.Code)
	}
}

func TestAdminRescueProbeChecksForSSHBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			_, _ = conn.Write([]byte("SSH-2.0-test-server\r\n"))
		}
	}()

	st := store.NewMemoryStore()
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:00:11"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRescueSSHPort(context.Background(), d.ID, port); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.FRPS.Host = "127.0.0.1"
	srv.FRPS.RemotePortStart = port
	srv.FRPS.RemotePortEnd = port
	body, _ := json.Marshal(map[string]string{"device_id": d.ID})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/rescue/probe", strings.NewReader(string(body)))
	req.Header.Set("X-TY-Admin-Token", "admin-test")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("probe status = %d: %s", w.Code, w.Body.String())
	}
	var result struct {
		Port         int    `json:"port"`
		Reachable    bool   `json:"reachable"`
		TunnelStatus string `json:"tunnel_status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Port != port || !result.Reachable || result.TunnelStatus != "ssh_ready" {
		t.Fatalf("unexpected probe result: %+v", result)
	}
}

func TestRescueProbeRequiresAdmin(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/rescue/probe", strings.NewReader(`{"device_id":"device"}`))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated rescue probe status = %d", w.Code)
	}
}

func TestRescuePortAssignmentIsAdminOnlyAndUnique(t *testing.T) {
	st := store.NewMemoryStore()
	first, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:00:21"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:00:22"})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.FRPS.RemotePortStart = 22000
	srv.FRPS.RemotePortEnd = 22099
	body := `{"device_id":"` + first.ID + `","port":22000}`
	unauth := httptest.NewRecorder()
	srv.ServeHTTP(unauth, httptest.NewRequest(http.MethodPost, "/api/v1/admin/devices/rescue-port", strings.NewReader(body)))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated rescue-port update status = %d", unauth.Code)
	}
	adminRequest := func(deviceID string) *httptest.ResponseRecorder {
		requestBody := `{"device_id":"` + deviceID + `","port":22000}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/devices/rescue-port", strings.NewReader(requestBody))
		req.Header.Set("X-TY-Admin-Token", "admin-test")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	if w := adminRequest(first.ID); w.Code != http.StatusOK {
		t.Fatalf("first rescue-port assignment status = %d: %s", w.Code, w.Body.String())
	}
	if w := adminRequest(second.ID); w.Code != http.StatusConflict {
		t.Fatalf("duplicate rescue-port assignment status = %d: %s", w.Code, w.Body.String())
	}
	if got, _ := st.GetDevice(context.Background(), first.ID); got.RescueSSHPort != 22000 {
		t.Fatalf("rescue port not persisted in memory store: %d", got.RescueSSHPort)
	}
}

func TestRescuePortAssignmentRequiresExplicitPort(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/devices/rescue-port", strings.NewReader(`{"device_id":"device"}`))
	req.Header.Set("X-TY-Admin-Token", "admin-test")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing rescue port status = %d", w.Code)
	}
}

func TestCustomerDeviceViewDoesNotExposeRescuePort(t *testing.T) {
	d := model.Device{ID: "d", Serial: "SERIAL", RescueSSHPort: 22000}
	b, err := json.Marshal(d.CustomerView())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "rescue_ssh_port") || strings.Contains(string(b), "22000") {
		t.Fatalf("customer device view exposed admin rescue mapping: %s", b)
	}
}
