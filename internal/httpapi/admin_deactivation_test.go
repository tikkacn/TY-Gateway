package httpapi

import (
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
	"tygateway/internal/frpauth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestAdminDeactivationAuthReplayAndFRPRoster(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	const mac = "02:00:00:00:92:01"
	_, _ = st.PrepareMACDeviceEnrollment(ctx, mac, "test unit", "", "")
	secret := strings.Repeat("a", 64)
	d, _, _ := st.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: secret})
	_ = st.SetRescueSSHPort(ctx, d.ID, 22000)
	d, _ = st.GetDevice(ctx, d.ID)
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	srv.FRPRosterToken = strings.Repeat("f", 64)
	send := func(path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("X-TY-Admin-Token", token)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	body := fmt.Sprintf(`{"device_id":%q,"expected_version":%d,"mac":%q,"confirm":"DEACTIVATE_DEVICE"}`, d.ID, d.ConfigVersion, mac)
	const endpoint = "/api/v1/admin/devices/deactivate"
	if w := send(endpoint, body, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized=%d", w.Code)
	}
	if w := send(endpoint, strings.Replace(body, "DEACTIVATE_DEVICE", "wrong", 1), "admin-test"); w.Code != http.StatusBadRequest {
		t.Fatalf("confirmation=%d", w.Code)
	}
	if w := send(endpoint, strings.Replace(body, mac, "02:00:00:00:92:02", 1), "admin-test"); w.Code != http.StatusConflict {
		t.Fatalf("MAC mismatch=%d", w.Code)
	}
	w := send(endpoint, body, "admin-test")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "pending_roster_refresh") || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "secret_hash") {
		t.Fatalf("reset response=%d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"config", "commands", "heartbeat"} {
		method, body := http.MethodGet, []byte(nil)
		if path == "heartbeat" {
			method, body = http.MethodPost, []byte(`{}`)
		}
		w = httptest.NewRecorder()
		srv.ServeHTTP(w, signedRequest(method, "/api/v1/device/"+d.ID+"/"+path, body, d.ID, auth.SecretHash(secret)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("revoked %s=%d", path, w.Code)
		}
	}
	registration := fmt.Sprintf(`{"mac":%q,"device_secret":%q}`, mac, secret)
	if w := send("/api/v1/devices/register", registration, ""); w.Code != http.StatusForbidden {
		t.Fatalf("revoked claim=%d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/frp/roster", nil)
	r.Header.Set("Authorization", "Bearer "+srv.FRPRosterToken)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	var roster frpauth.Roster
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &roster) != nil || len(roster.Entries) != 0 {
		t.Fatalf("revoked roster=%d %s", w.Code, w.Body.String())
	}
	if w := send("/api/v1/devices/register", strings.Replace(registration, secret, strings.Repeat("b", 64), 1), ""); w.Code != http.StatusCreated {
		t.Fatalf("fresh claim=%d %s", w.Code, w.Body.String())
	}
	if w := send(endpoint, body, "admin-test"); w.Code != http.StatusNotFound {
		t.Fatalf("stale drawer reset=%d", w.Code)
	}
}

func TestAutoFRPDoesNotReuseStillListeningPort(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	st := store.NewMemoryStore()
	d, _, _ := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:92:03"})
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	srv.AutoFRP = testOIDCAutoFRP("127.0.0.1")
	srv.AutoFRPPortStart, srv.AutoFRPPortEnd = port, port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := srv.allocateAutoFRPPort(ctx, d.ID); err != store.ErrLimit {
		t.Fatalf("occupied port allocation=%v", err)
	}
	_ = listener.Close()
	if got, err := srv.allocateAutoFRPPort(ctx, d.ID); err != nil || got != port {
		t.Fatalf("released port allocation=%d %v", got, err)
	}
}

func TestAdminDeactivationRejectsCrossOriginSession(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "", []byte("0123456789abcdef0123456789abcdef"))
	srv.AdminPassword = "test-password"
	r := httptest.NewRequest(http.MethodPost, "https://oec.example/api/v1/admin/login", strings.NewReader(`{"password":"test-password"}`))
	r.Header.Set("Origin", "https://oec.example")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK || len(w.Result().Cookies()) != 1 {
		t.Fatal("test login failed")
	}
	cookie := w.Result().Cookies()[0]
	r = httptest.NewRequest(http.MethodPost, "https://oec.example/api/v1/admin/devices/deactivate", strings.NewReader(`{}`))
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin reset=%d", w.Code)
	}
}
