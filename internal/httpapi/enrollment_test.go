package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestPreparedMACClaimIsAtomicAndGatesSensitiveConfig(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	request := func(method, path, body string, admin bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if admin {
			r.Header.Set("X-TY-Admin-Token", "admin-test")
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	if got := request(http.MethodPost, "/api/v1/admin/enrollments", `{"mac":"AA:BB:CC:DD:EE:01"}`, false); got.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated preparation status = %d", got.Code)
	}
	prepared := request(http.MethodPost, "/api/v1/admin/enrollments", `{"mac":"AA:BB:CC:DD:EE:01","note":"first unit"}`, true)
	if prepared.Code != http.StatusCreated {
		t.Fatalf("prepare status=%d body=%s", prepared.Code, prepared.Body.String())
	}
	var preparedResult struct {
		ActivationCode string                 `json:"activation_code"`
		Enrollment     model.DeviceEnrollment `json:"enrollment"`
	}
	if err := json.Unmarshal(prepared.Body.Bytes(), &preparedResult); err != nil || preparedResult.ActivationCode != "" || preparedResult.Enrollment.ClaimMode != "mac" {
		t.Fatalf("MAC allowlist response must not contain a claim secret: %v %#v", err, preparedResult)
	}
	listed := request(http.MethodGet, "/api/v1/admin/enrollments", "", true)
	if listed.Code != http.StatusOK || strings.Contains(listed.Body.String(), "activation_code") {
		t.Fatal("enrollment list should contain no activation secret")
	}
	secret := strings.Repeat("a", 64)
	registration := `{"mac":"AA:BB:CC:DD:EE:01","device_secret":"` + secret + `"}`
	if got := request(http.MethodPost, "/api/v1/devices/register", `{"mac":"AA:BB:CC:DD:EE:01"}`, false); got.Code != http.StatusForbidden {
		t.Fatalf("claim without a device-generated secret status = %d", got.Code)
	}
	if got := request(http.MethodPost, "/api/v1/devices/register", `{"mac":"AA:BB:CC:DD:EE:02","device_secret":"`+secret+`"}`, false); got.Code != http.StatusForbidden {
		t.Fatalf("unknown MAC status = %d", got.Code)
	}
	registered := request(http.MethodPost, "/api/v1/devices/register", registration, false)
	if registered.Code != http.StatusCreated || strings.Contains(registered.Body.String(), "activation_code") {
		t.Fatalf("valid MAC claim status=%d body=%s", registered.Code, registered.Body.String())
	}
	var result struct {
		Credentials struct {
			DeviceID     string `json:"device_id"`
			DeviceSecret string `json:"device_secret"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	d, err := st.GetDevice(ctx, result.Credentials.DeviceID)
	if err != nil || d.State != model.DeviceEnabled || d.Note != "first unit" {
		t.Fatalf("approved device not activated: %#v %v", d, err)
	}
	if got := request(http.MethodPost, "/api/v1/devices/register", registration, false); got.Code != http.StatusCreated {
		t.Fatalf("idempotent retry status = %d", got.Code)
	}
	if got := request(http.MethodPost, "/api/v1/devices/register", `{"mac":"AA:BB:CC:DD:EE:01","device_secret":"`+strings.Repeat("b", 64)+`"}`, false); got.Code != http.StatusForbidden {
		t.Fatalf("retry with different secret status = %d", got.Code)
	}
	config := signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil, d.ID, auth.SecretHash(result.Credentials.DeviceSecret))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, config)
	if w.Code != http.StatusOK {
		t.Fatalf("activated device config status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPendingDeviceCannotFetchConfigWhenActivationRequired(t *testing.T) {
	st := store.NewMemoryStore()
	d, secret, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:70:01"})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	r := signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil, d.ID, auth.SecretHash(secret))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("pending config status = %d", w.Code)
	}
	listed := httptest.NewRecorder()
	srv.ServeHTTP(listed, signedRequest(http.MethodPost, "/api/v1/device/"+d.ID+"/heartbeat", []byte(`{}`), d.ID, auth.SecretHash(secret)))
	if listed.Code == http.StatusForbidden {
		t.Fatal("pending device must still be able to report health")
	}
}

func TestActivationGatePreservesExistingEnabledRescueDevice(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	d, secret, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:70:02"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = st.UpdateDevice(ctx, d.ID, model.DeviceEnabled, "existing", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRescueSSHPort(ctx, d.ID, 22000); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	srv.Rescue = &model.RescueConfig{Host: "127.0.0.1", Port: 7001}
	srv.AutoFRP = &model.AutoFRPConfig{Host: "127.0.0.1", ControlPort: 7002, TLSCA: "public-ca"}
	srv.AutoFRPPortStart, srv.AutoFRPPortEnd = 22100, 22199
	r := signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil, d.ID, auth.SecretHash(secret))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("existing enabled device blocked: %d %s", w.Code, w.Body.String())
	}
	var config model.DeviceConfig
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil || config.Rescue == nil || config.Rescue.RemotePort != 22000 || config.AutoFRP != nil {
		t.Fatalf("existing 22000 rescue assignment changed: %v %s", err, w.Body.String())
	}
	stored, err := st.GetDevice(ctx, d.ID)
	if err != nil || stored.RescueSSHPort != 22000 {
		t.Fatalf("stored rescue assignment changed: %d %v", stored.RescueSSHPort, err)
	}
}

func TestMACClaimReceivesOnlyIsolatedAutoFRPConfig(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	srv.AutoFRP = &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7002, TLSCA: "public-ca"}
	srv.AutoFRPPortStart, srv.AutoFRPPortEnd = 22100, 22199
	srv.FRPRosterPortStart, srv.FRPRosterPortEnd = 22100, 22199
	admin := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrollments", strings.NewReader(`{"mac":"02:00:00:00:70:03","note":"pilot"}`))
	admin.Header.Set("X-TY-Admin-Token", "admin-test")
	prepared := httptest.NewRecorder()
	srv.ServeHTTP(prepared, admin)
	if prepared.Code != http.StatusCreated || strings.Contains(prepared.Body.String(), "activation_code") {
		t.Fatalf("MAC pre-registration failed or returned a claim secret: %d %s", prepared.Code, prepared.Body.String())
	}
	secret := strings.Repeat("c", 64)
	register := httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", strings.NewReader(`{"mac":"020000007003","device_secret":"`+secret+`"}`))
	registered := httptest.NewRecorder()
	srv.ServeHTTP(registered, register)
	if registered.Code != http.StatusCreated {
		t.Fatalf("pre-registered MAC did not auto-claim: %d %s", registered.Code, registered.Body.String())
	}
	var registeredBody struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &registeredBody); err != nil || registeredBody.Device.ID == "" {
		t.Fatalf("invalid claim response: %v", err)
	}
	d, err := st.GetDevice(ctx, registeredBody.Device.ID)
	if err != nil || d.RescueSSHPort != 22100 {
		t.Fatalf("device did not receive a reserved isolated FRP port: %#v %v", d, err)
	}
	configRequest := signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil, d.ID, auth.SecretHash(secret))
	configResponse := httptest.NewRecorder()
	srv.ServeHTTP(configResponse, configRequest)
	var config model.DeviceConfig
	if err := json.Unmarshal(configResponse.Body.Bytes(), &config); err != nil || config.AutoFRP == nil || config.AutoFRP.ControlPort != 7002 || config.AutoFRP.RemotePort != 22100 || config.AutoFRP.Host != "frp.example.test" {
		t.Fatalf("device did not receive its isolated automatic FRP settings: %v %s", err, configResponse.Body.String())
	}
	if config.Rescue != nil && config.Rescue.RemotePort == 22000 {
		t.Fatal("automatic FRP response crossed into the existing 22000 rescue channel")
	}
}

func TestMACClaimWaitsForIsolatedFRPWithoutReservingLegacyPort(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	srv.Rescue = &model.RescueConfig{Host: "127.0.0.1", Port: 7001}
	srv.FRPS.Host = "127.0.0.1"
	srv.AutoFRPPortStart, srv.AutoFRPPortEnd = 22100, 22199

	prepare := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrollments", strings.NewReader(`{"mac":"02:00:00:00:70:04"}`))
	prepare.Header.Set("X-TY-Admin-Token", "admin-test")
	prepared := httptest.NewRecorder()
	srv.ServeHTTP(prepared, prepare)
	if prepared.Code != http.StatusCreated {
		t.Fatalf("MAC preparation failed: %d %s", prepared.Code, prepared.Body.String())
	}
	secret := strings.Repeat("d", 64)
	register := httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", strings.NewReader(`{"mac":"020000007004","device_secret":"`+secret+`"}`))
	registered := httptest.NewRecorder()
	srv.ServeHTTP(registered, register)
	if registered.Code != http.StatusCreated {
		t.Fatalf("MAC claim failed: %d %s", registered.Code, registered.Body.String())
	}
	var result struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &result); err != nil || result.Device.ID == "" {
		t.Fatalf("invalid MAC claim response: %v", err)
	}
	config := func() model.DeviceConfig {
		r := signedRequest(http.MethodGet, "/api/v1/device/"+result.Device.ID+"/config", nil, result.Device.ID, auth.SecretHash(secret))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("device config failed: %d %s", w.Code, w.Body.String())
		}
		var got model.DeviceConfig
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := config(); got.AutoFRP != nil {
		t.Fatalf("automatic FRP was advertised before the isolated listener was configured: %#v", got.AutoFRP)
	}
	before, err := st.GetDevice(ctx, result.Device.ID)
	if err != nil || before.RescueSSHPort != 0 {
		t.Fatalf("MAC claim consumed a legacy port: %#v %v", before, err)
	}

	srv.AutoFRP = &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7002, TLSCA: "public-ca"}
	if got := config(); got.AutoFRP == nil || got.AutoFRP.RemotePort != 22100 {
		t.Fatalf("isolated FRP was not assigned after activation: %#v", got.AutoFRP)
	}
	after, err := st.GetDevice(ctx, result.Device.ID)
	if err != nil || after.RescueSSHPort != 22100 {
		t.Fatalf("isolated FRP port was not persisted: %#v %v", after, err)
	}
}
