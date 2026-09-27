package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/identity"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestDeviceLifecycleAndSecretBoundaries(t *testing.T) {
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test-token", []byte("0123456789abcdef0123456789abcdef"))
	registerBody := []byte(`{"mac":"aa:bb:cc:dd:ee:01","agent_version":"sim","firmware_version":"0.1.0"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", bytes.NewReader(registerBody))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", w.Code, w.Body.String())
	}
	var registered struct {
		Device struct {
			ID     string `json:"id"`
			Serial string `json:"serial"`
		} `json:"device"`
		Credentials struct {
			DeviceID     string `json:"device_id"`
			DeviceSecret string `json:"device_secret"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	if registered.Device.Serial != "AABBCCDDEE01" || registered.Credentials.DeviceSecret == "" {
		t.Fatalf("bad registration: %#v", registered)
	}
	dup := httptest.NewRecorder()
	srv.ServeHTTP(dup, httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", bytes.NewReader(registerBody)))
	if dup.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d", dup.Code)
	}
	if strings.Contains(dup.Body.String(), registered.Credentials.DeviceSecret) {
		t.Fatal("duplicate response leaked device secret")
	}

	deviceID := registered.Device.ID
	secretHash := auth.SecretHash(registered.Credentials.DeviceSecret)
	report := []byte(`{"status":"ok","agent_version":"sim-2"}`)
	request := signedRequest(http.MethodPost, "/api/v1/device/"+deviceID+"/heartbeat", report, deviceID, secretHash)
	resp := httptest.NewRecorder()
	srv.ServeHTTP(resp, request)
	if resp.Code != http.StatusOK {
		t.Fatalf("heartbeat status=%d body=%s", resp.Code, resp.Body.String())
	}
	configReq := signedRequest(http.MethodGet, "/api/v1/device/"+deviceID+"/config", nil, deviceID, secretHash)
	configResp := httptest.NewRecorder()
	srv.ServeHTTP(configResp, configReq)
	if configResp.Code != http.StatusOK {
		t.Fatalf("config status=%d body=%s", configResp.Code, configResp.Body.String())
	}
	if strings.Contains(configResp.Body.String(), registered.Credentials.DeviceSecret) || strings.Contains(configResp.Body.String(), secretHash) {
		t.Fatal("config leaked device credential")
	}

	subBody := []byte(`{"name":"test-sub","provider":"v2board","url":"https://sub.example.invalid/token"}`)
	subReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/subscriptions", bytes.NewReader(subBody))
	subReq.Header.Set("X-TY-Admin-Token", "admin-test-token")
	subResp := httptest.NewRecorder()
	srv.ServeHTTP(subResp, subReq)
	if subResp.Code != http.StatusCreated {
		t.Fatalf("sub status=%d body=%s", subResp.Code, subResp.Body.String())
	}
	if strings.Contains(subResp.Body.String(), "token") {
		t.Fatal("subscription URL leaked in admin response")
	}
}

func TestRootRedirectsToAdmin(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "admin-test-token", []byte("0123456789abcdef0123456789abcdef"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("root status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Location"); got != "/admin" {
		t.Fatalf("root location=%q", got)
	}
}

func TestDeviceRegistrationAllocatesLowestRescuePort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	occupied := listener.Addr().(*net.TCPAddr).Port
	if occupied > 65533 {
		t.Skip("test host returned a port too close to the upper bound")
	}
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test-token", []byte("0123456789abcdef0123456789abcdef"))
	srv.Rescue = &model.RescueConfig{Name: "Shanghai", Host: "127.0.0.1", Port: 22}
	srv.FRPS.RemotePortStart = occupied
	srv.FRPS.RemotePortEnd = occupied + 2
	register := func(mac string) int {
		body := []byte(`{"mac":"` + mac + `"}`)
		resp := httptest.NewRecorder()
		srv.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", bytes.NewReader(body)))
		if resp.Code != http.StatusCreated {
			t.Fatalf("register status=%d body=%s", resp.Code, resp.Body.String())
		}
		var result struct {
			Device struct {
				ID string `json:"id"`
			} `json:"device"`
			Rescue *model.RescueConfig `json:"rescue"`
		}
		if err := json.Unmarshal(resp.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Rescue == nil || result.Rescue.RemotePort == 0 {
			t.Fatalf("registration did not return rescue metadata: %s", resp.Body.String())
		}
		return result.Rescue.RemotePort
	}
	firstPort := register("02:00:00:00:30:01")
	secondPort := register("02:00:00:00:30:02")
	if firstPort != occupied+1 || secondPort != occupied+2 {
		t.Fatalf("automatic rescue ports = %d, %d; want %d, %d", firstPort, secondPort, occupied+1, occupied+2)
	}
}

func TestDaeReportedSubscriptionCountAndURLBoundary(t *testing.T) {
	const (
		adminToken = "admin-test-token"
		subURL     = "https://provider.example.invalid/sub?token=private-test-token"
	)
	st := store.NewMemoryStore()
	srv := NewServer(st, adminToken, []byte("0123456789abcdef0123456789abcdef"))
	registerBody := []byte(`{"mac":"02:00:00:00:00:25","agent_version":"test"}`)
	registerResp := httptest.NewRecorder()
	srv.ServeHTTP(registerResp, httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", bytes.NewReader(registerBody)))
	if registerResp.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", registerResp.Code, registerResp.Body.String())
	}
	var registered struct {
		Device struct {
			ID     string `json:"id"`
			Serial string `json:"serial"`
		} `json:"device"`
		Credentials struct {
			DeviceID     string `json:"device_id"`
			DeviceSecret string `json:"device_secret"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(registerResp.Body.Bytes(), &registered); err != nil {
		t.Fatal(err)
	}
	admin := func(method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("X-TY-Admin-Token", adminToken)
		resp := httptest.NewRecorder()
		srv.ServeHTTP(resp, req)
		return resp
	}
	subResp := admin(http.MethodPost, "/api/v1/admin/subscriptions", []byte(`{"name":"test","provider":"v2board","url":"`+subURL+`"}`))
	if subResp.Code != http.StatusCreated {
		t.Fatalf("subscription create status=%d body=%s", subResp.Code, subResp.Body.String())
	}
	var sub struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(subResp.Body.Bytes(), &sub); err != nil || sub.ID == "" {
		t.Fatalf("subscription response invalid: %v", err)
	}
	bindResp := admin(http.MethodPost, "/api/v1/admin/devices/bind-subscription", []byte(`{"device_id":"`+registered.Device.ID+`","subscription_id":"`+sub.ID+`"}`))
	if bindResp.Code != http.StatusOK {
		t.Fatalf("bind status=%d body=%s", bindResp.Code, bindResp.Body.String())
	}
	secretHash := auth.SecretHash(registered.Credentials.DeviceSecret)
	configResp := httptest.NewRecorder()
	srv.ServeHTTP(configResp, signedRequest(http.MethodGet, "/api/v1/device/"+registered.Device.ID+"/config", nil, registered.Device.ID, secretHash))
	if configResp.Code != http.StatusOK || !strings.Contains(configResp.Body.String(), subURL) {
		t.Fatalf("authenticated device config did not receive its URL: status=%d body=%s", configResp.Code, configResp.Body.String())
	}
	if got := configResp.Header().Get("Cache-Control"); got != "no-store, private" {
		t.Fatalf("sensitive device config is cacheable: Cache-Control=%q", got)
	}
	if !strings.Contains(configResp.Body.String(), `"dae_subscription_managed":true`) {
		t.Fatal("device config did not delegate parsing to dae")
	}

	accessDevice, accessToken, err := st.RotateCustomerAccess(context.Background(), registered.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	loginBody, _ := json.Marshal(map[string]string{"device_code": accessDevice.Serial, "access_token": accessToken})
	loginResp := httptest.NewRecorder()
	srv.ServeHTTP(loginResp, httptest.NewRequest(http.MethodPost, "/api/v1/customer/login", bytes.NewReader(loginBody)))
	if loginResp.Code != http.StatusOK {
		t.Fatalf("customer login status=%d body=%s", loginResp.Code, loginResp.Body.String())
	}
	var login struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.Unmarshal(loginResp.Body.Bytes(), &login); err != nil || login.SessionToken == "" {
		t.Fatalf("customer login response invalid: %v", err)
	}
	customerReq := httptest.NewRequest(http.MethodGet, "/api/v1/customer/me", nil)
	customerReq.Header.Set("Authorization", "Bearer "+login.SessionToken)
	customerResp := httptest.NewRecorder()
	srv.ServeHTTP(customerResp, customerReq)
	if customerResp.Code != http.StatusOK {
		t.Fatalf("customer state status=%d body=%s", customerResp.Code, customerResp.Body.String())
	}
	if strings.Contains(customerResp.Body.String(), subURL) || strings.Contains(customerResp.Body.String(), "private-test-token") {
		t.Fatal("customer API leaked the subscription URL")
	}

	refreshResp := admin(http.MethodPost, "/api/v1/admin/subscriptions/refresh", []byte(`{"id":"`+sub.ID+`"}`))
	if refreshResp.Code != http.StatusAccepted || !strings.Contains(refreshResp.Body.String(), `"parser":"dae_on_device"`) {
		t.Fatalf("refresh was not delegated to device dae: status=%d body=%s", refreshResp.Code, refreshResp.Body.String())
	}
	report := []byte(`{"status":"ok","dae_subscription_id":"` + sub.ID + `","dae_status":"ok","dae_node_count":25}`)
	heartbeatResp := httptest.NewRecorder()
	srv.ServeHTTP(heartbeatResp, signedRequest(http.MethodPost, "/api/v1/device/"+registered.Device.ID+"/heartbeat", report, registered.Device.ID, secretHash))
	if heartbeatResp.Code != http.StatusOK {
		t.Fatalf("dae heartbeat status=%d body=%s", heartbeatResp.Code, heartbeatResp.Body.String())
	}
	subscriptions, err := st.ListSubscriptions(context.Background())
	if err != nil || len(subscriptions) != 1 || subscriptions[0].NodeCount != 25 || subscriptions[0].Status != "ok" {
		t.Fatalf("dae count was not authoritative: subscriptions=%#v err=%v", subscriptions, err)
	}
	errorReport := []byte(`{"status":"ok","dae_subscription_id":"` + sub.ID + `","dae_status":"error","dae_node_count":0}`)
	errorResp := httptest.NewRecorder()
	srv.ServeHTTP(errorResp, signedRequest(http.MethodPost, "/api/v1/device/"+registered.Device.ID+"/heartbeat", errorReport, registered.Device.ID, secretHash))
	if errorResp.Code != http.StatusOK {
		t.Fatalf("dae error report status=%d body=%s", errorResp.Code, errorResp.Body.String())
	}
	subscriptions, err = st.ListSubscriptions(context.Background())
	if err != nil || len(subscriptions) != 1 || subscriptions[0].NodeCount != 25 || subscriptions[0].Status != "error" {
		t.Fatalf("dae failure destroyed last-known-good count: subscriptions=%#v err=%v", subscriptions, err)
	}
	commandsResp := httptest.NewRecorder()
	srv.ServeHTTP(commandsResp, signedRequest(http.MethodGet, "/api/v1/device/"+registered.Device.ID+"/commands", nil, registered.Device.ID, secretHash))
	if commandsResp.Code != http.StatusOK || !strings.Contains(commandsResp.Body.String(), `"command":"refresh_subscription"`) {
		t.Fatalf("subscription refresh did not queue its dedicated command: status=%d body=%s", commandsResp.Code, commandsResp.Body.String())
	}
	if rejected := admin(http.MethodPost, "/api/v1/admin/devices/command", []byte(`{"device_id":"`+registered.Device.ID+`","command":"run_shell"}`)); rejected.Code != http.StatusBadRequest {
		t.Fatalf("arbitrary command was accepted: status=%d body=%s", rejected.Code, rejected.Body.String())
	}
}

func signedRequest(method, path string, body []byte, deviceID, key string) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	ts := time.Now().Unix()
	nonce := identity.NewID()
	r.Header.Set("X-TY-Device", deviceID)
	r.Header.Set("X-TY-Timestamp", fmt.Sprint(ts))
	r.Header.Set("X-TY-Nonce", nonce)
	r.Header.Set("X-TY-Signature", auth.Sign(method, path, body, ts, nonce, key))
	return r
}
