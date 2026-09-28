package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/frpauth"
	"tygateway/internal/httpapi"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

// Exercises the real Agent enrollment client against the real in-memory Cloud
// HTTP API. The first response is deliberately lost after Cloud commits, which
// models a power/network interruption and proves a rerun reuses the durable
// pending identity instead of creating a duplicate device.
func TestMACAutoEnrollmentIsRetrySafeAndAllocatesFRP(t *testing.T) {
	const mac = "30A61209E431" // Agent canonical format returned by interfaceMAC.
	ctx := context.Background()
	st := store.NewMemoryStore()
	cloud := httpapi.NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	cloud.RequireActivation = true
	cloud.LegacyFRPRetired = true
	cloud.AutoFRP = testAutoFRPConfig("frp.example.test", 0, testAutoFRPCA(t))
	cloud.AutoFRPPortStart, cloud.AutoFRPPortEnd = 22000, 22999
	cloud.FRPRosterPortStart, cloud.FRPRosterPortEnd = 22000, 22999

	adminRequest := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrollments", strings.NewReader(`{"mac":"30:A6:12:09:E4:31","note":"oec2-pilot"}`))
	adminRequest.Header.Set("X-TY-Admin-Token", "admin-test")
	adminResponse := httptest.NewRecorder()
	cloud.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusCreated || strings.Contains(adminResponse.Body.String(), "activation_code") {
		t.Fatalf("MAC pre-registration failed or disclosed an activation secret: HTTP %d", adminResponse.Code)
	}

	var registerCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/devices/register" && registerCalls.Add(1) == 1 {
			committed := httptest.NewRecorder()
			cloud.ServeHTTP(committed, r)
			if committed.Code != http.StatusCreated {
				t.Errorf("Cloud did not commit the first claim before simulated response loss: HTTP %d", committed.Code)
				http.Error(w, "cloud claim failed", http.StatusBadGateway)
				return
			}
			http.Error(w, "simulated lost response", http.StatusBadGateway)
			return
		}
		cloud.ServeHTTP(w, r)
	}))
	defer api.Close()

	stateDir := t.TempDir()
	a := &agent{
		server:        api.URL,
		stateDir:      stateDir,
		client:        api.Client(),
		logger:        log.New(os.Stderr, "test-agent: ", 0),
		interfaceName: "eth0",
	}
	if err := a.enrollWithMAC(ctx, "eth0", mac); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("first enrollment should report the simulated lost response; got %v", err)
	}

	pendingPath := filepath.Join(stateDir, "pending-enrollment.json")
	pendingBytes, err := os.ReadFile(pendingPath)
	if err != nil {
		t.Fatalf("durable pending identity was not retained after uncertain response: %v", err)
	}
	var pending pendingIdentity
	if err := json.Unmarshal(pendingBytes, &pending); err != nil || !strings.EqualFold(pending.MAC, mac) || !validSecret(pending.DeviceSecret) {
		t.Fatalf("pending identity is invalid after interrupted enrollment: %v", err)
	}

	if err := a.enrollWithMAC(ctx, "eth0", mac); err != nil {
		t.Fatalf("retry did not complete enrollment using the same pending identity: %v", err)
	}
	if registerCalls.Load() != 2 {
		t.Fatalf("expected exactly two enrollment attempts, got %d", registerCalls.Load())
	}
	if _, err := os.Stat(pendingPath); !os.IsNotExist(err) {
		t.Fatalf("pending identity should be removed only after credentials are saved; stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "activation.json")); !os.IsNotExist(err) {
		t.Fatalf("MAC auto-enrollment should not require or create a one-time activation file; stat err=%v", err)
	}

	credentialsBytes, err := os.ReadFile(filepath.Join(stateDir, "credentials.json"))
	if err != nil {
		t.Fatalf("credentials were not persisted locally: %v", err)
	}
	var saved credentialState
	if err := json.Unmarshal(credentialsBytes, &saved); err != nil || saved.DeviceID == "" || saved.DeviceSecret != pending.DeviceSecret || !strings.EqualFold(saved.MAC, mac) {
		t.Fatalf("persisted credentials do not match the durable enrollment identity: %v", err)
	}
	device, err := st.GetDevice(ctx, saved.DeviceID)
	if err != nil || !strings.EqualFold(device.Serial, mac) || device.RescueSSHPort != 22000 {
		t.Fatalf("Cloud device identity or first automatic FRP port is wrong: port=%d err=%v", device.RescueSSHPort, err)
	}
	enrollments, err := st.ListDeviceEnrollments(ctx)
	if err != nil || len(enrollments) != 1 || enrollments[0].DeviceID != saved.DeviceID || enrollments[0].ClaimedAt == nil {
		t.Fatalf("claim did not atomically bind exactly one pre-registered MAC: records=%d err=%v", len(enrollments), err)
	}
	if got := a.stateValue(); got.DeviceID != saved.DeviceID || got.DeviceSecret != saved.DeviceSecret {
		t.Fatal("Agent did not retain the Cloud-issued credentials in memory")
	}
	configBytes, status, err := a.signedRequest(ctx, http.MethodGet, "/api/v1/device/"+saved.DeviceID+"/config", nil)
	if err != nil || status != http.StatusOK {
		t.Fatalf("Agent could not authenticate and fetch its post-enrollment configuration: HTTP %d err=%v", status, err)
	}
	var config model.DeviceConfig
	if err := json.Unmarshal(configBytes, &config); err != nil || config.AutoFRP == nil || config.AutoFRP.ControlPort != 7001 || config.AutoFRP.RemotePort != 22000 || config.AutoFRP.Host != "frp.example.test" || config.AutoFRP.OIDCIssuer != testFRPOIDCIssuer || config.AutoFRP.OIDCTokenEndpoint != testFRPOIDCIssuer+"/token" {
		t.Fatalf("Cloud did not deliver the assigned automatic FRP config: err=%v auto_frp=%#v", err, config.AutoFRP)
	}
	t.Setenv("TY_GATEWAY_TEST_FRPC_HELPER", "1")
	t.Setenv("TY_GATEWAY_TEST_FRPC_MODE", "run")
	a.autoFRP = newAutoFRPManager(filepath.Join(stateDir, "frpc-auto.toml"), os.Args[0])
	t.Cleanup(func() { _ = a.autoFRP.Apply(ctx, a.stateValue(), nil) })
	a.reconcileAutoFRP(ctx, config.AutoFRP)
	if a.autoFRP.cmd == nil {
		t.Fatal("Agent received the Cloud FRP settings but did not start its FRPC client")
	}
	frpcConfig, err := os.ReadFile(a.autoFRP.configPath)
	credential, credentialErr := frpauth.Credential(auth.SecretHash(saved.DeviceSecret), saved.DeviceID, 22000)
	if err != nil || credentialErr != nil || !strings.Contains(string(frpcConfig), "serverPort = 7001") || !strings.Contains(string(frpcConfig), "remotePort = 22000") || !strings.Contains(string(frpcConfig), `auth.oidc.clientSecret = "`+credential+`"`) {
		t.Fatalf("Agent did not stage the assigned FRP client configuration: %v", err)
	}
	devices, err := st.ListDevices(ctx, time.Minute)
	if err != nil || len(devices) != 1 {
		t.Fatalf("retry created duplicate cloud devices: count=%d err=%v", len(devices), err)
	}
	if info, err := os.Stat(filepath.Join(stateDir, "credentials.json")); err != nil {
		t.Fatalf("credentials stat failed: %v", err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		t.Fatalf("credentials are not owner-only: mode %o", info.Mode().Perm())
	}
}
