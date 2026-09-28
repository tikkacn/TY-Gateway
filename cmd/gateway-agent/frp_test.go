package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/frpauth"
	"tygateway/internal/model"
)

// The test binary doubles as a tiny frpc stand-in when launched by the manager.
// It never opens a listener or connects to a network endpoint.
func init() {
	if os.Getenv("TY_GATEWAY_TEST_FRPC_HELPER") != "1" {
		return
	}
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	if os.Args[1] == "verify" {
		os.Exit(0)
	}
	if os.Args[1] != "-c" {
		os.Exit(2)
	}
	if failHost := os.Getenv("TY_GATEWAY_TEST_FRPC_FAIL_HOST"); failHost != "" && len(os.Args) > 2 {
		config, err := os.ReadFile(os.Args[2])
		if err == nil && strings.Contains(string(config), failHost) {
			os.Exit(1)
		}
	}
	if os.Getenv("TY_GATEWAY_TEST_FRPC_MODE") == "exit" {
		os.Exit(1)
	}
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	timer := time.NewTimer(5 * time.Second)
	select {
	case <-interrupt:
	case <-timer.C:
	}
	timer.Stop()
	os.Exit(0)
}

func TestRenderAutoFRPConfigUsesDeviceScopedCredentialAndSeparatePort(t *testing.T) {
	state := credentialState{DeviceID: "device-abcd", DeviceSecret: strings.Repeat("a", 64)}
	config := &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7001, RemotePort: 22017}
	text, gotCredential, err := renderAutoFRPConfig(state, config, "/var/lib/ty-gateway/frp-auto-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	wantCredential, err := frpauth.Credential(auth.SecretHash(state.DeviceSecret), state.DeviceID, config.RemotePort)
	if err != nil || gotCredential != wantCredential {
		t.Fatalf("FRP credential derivation mismatch: %v", err)
	}
	for _, expected := range []string{
		"serverPort = 7001",
		"remotePort = 22017",
		"transport.tls.trustedCaFile",
		"metadatas.device_id = \"device-abcd\"",
		"metadatas.rescue_key = \"" + wantCredential + "\"",
		"name = \"ssh-rescue\"",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated FRPC config missing %q", expected)
		}
	}
	if strings.Contains(text, "name = \"device-abcd.ssh-rescue\"") {
		t.Fatal("proxy name must not include the device ID because FRP adds the global user prefix")
	}
	if strings.Contains(text, "auth.token") {
		t.Fatal("generated FRPC config embeds a shared token")
	}
	config.RemotePort = 22000
	if text, _, err := renderAutoFRPConfig(state, config, "/var/lib/ty-gateway/frp-auto-ca.pem"); err != nil || !strings.Contains(text, "remotePort = 22000") {
		t.Fatalf("first unified auto-FRP port was rejected: %v", err)
	}
}

func TestRenderAutoFRPConfigRejectsUnsafeOrLegacyInputs(t *testing.T) {
	state := credentialState{DeviceID: "device-abcd", DeviceSecret: strings.Repeat("a", 64)}
	for _, config := range []*model.AutoFRPConfig{
		{Host: "frp.example.test\nloginFailExit = false", ControlPort: 7001, RemotePort: 22017},
		{Host: "frp.example.test", ControlPort: 7002, RemotePort: 22017},
		{Host: "frp.example.test", ControlPort: 0, RemotePort: 22000},
		{Host: "frp.example.test", ControlPort: 7001, RemotePort: 0},
		{Host: "frp.example.test", ControlPort: 7001, RemotePort: 23000},
	} {
		if _, _, err := renderAutoFRPConfig(state, config, "/tmp/ca.pem"); err == nil {
			t.Fatalf("unsafe automatic FRP config was accepted: %#v", config)
		}
	}
}

func TestAutoFRPManagerApplyReusesAndStopsClient(t *testing.T) {
	t.Setenv("TY_GATEWAY_TEST_FRPC_HELPER", "1")
	t.Setenv("TY_GATEWAY_TEST_FRPC_MODE", "run")
	state := credentialState{DeviceID: "device-test", DeviceSecret: strings.Repeat("a", 64)}
	config := &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7001, RemotePort: 22000, TLSCA: testAutoFRPCA(t)}
	manager := newAutoFRPManager(filepath.Join(t.TempDir(), "frpc-auto.toml"), os.Args[0])

	if err := manager.Apply(context.Background(), state, config); err != nil {
		t.Fatalf("first FRP apply: %v", err)
	}
	if manager.cmd == nil {
		t.Fatal("FRP client was not started")
	}
	firstPID := manager.cmd.Process.Pid
	if err := manager.Apply(context.Background(), state, config); err != nil {
		t.Fatalf("idempotent FRP apply: %v", err)
	}
	if manager.cmd == nil || manager.cmd.Process.Pid != firstPID {
		t.Fatal("identical FRP configuration spawned a duplicate client")
	}
	if err := manager.Apply(context.Background(), state, nil); err != nil {
		t.Fatalf("FRP revoke: %v", err)
	}
	if manager.cmd != nil || manager.done != nil {
		t.Fatal("FRP client remained tracked after revoke")
	}
	for _, path := range []string{manager.configPath, manager.caPath, manager.configPath + ".next"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("revoked FRP file remains at %s: %v", path, err)
		}
	}
}

func TestAutoFRPManagerRejectsClientThatExitsImmediately(t *testing.T) {
	t.Setenv("TY_GATEWAY_TEST_FRPC_HELPER", "1")
	t.Setenv("TY_GATEWAY_TEST_FRPC_MODE", "exit")
	state := credentialState{DeviceID: "device-test", DeviceSecret: strings.Repeat("b", 64)}
	config := &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7001, RemotePort: 22000, TLSCA: testAutoFRPCA(t)}
	manager := newAutoFRPManager(filepath.Join(t.TempDir(), "frpc-auto.toml"), os.Args[0])

	if err := manager.Apply(context.Background(), state, config); err == nil {
		t.Fatal("FRP apply succeeded although its client exited immediately")
	}
	if manager.cmd != nil {
		t.Fatal("failed FRP client remains tracked")
	}
	for _, path := range []string{manager.configPath, manager.caPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("failed FRP apply left an active file at %s: %v", path, err)
		}
	}
}

func TestAutoFRPCloudOmissionIsVisibleWithoutLoggingConfigurationData(t *testing.T) {
	var logs bytes.Buffer
	a := &agent{
		autoFRP: newAutoFRPManager(filepath.Join(t.TempDir(), "frpc-auto.toml"), "missing-frpc"),
		logger:  log.New(&logs, "", 0),
	}
	ctx := context.Background()
	a.reconcileAutoFRP(ctx, &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7001, RemotePort: 22000, TLSCA: "sensitive-config-marker"})
	a.reconcileAutoFRP(ctx, nil)
	a.reconcileAutoFRP(ctx, nil)

	if got := logs.String(); strings.Count(got, "automatic FRP config absent from Cloud") != 1 {
		t.Fatalf("missing Cloud FRP configuration should be reported once, got logs: %q", got)
	}
	if strings.Contains(logs.String(), "sensitive-config-marker") {
		t.Fatal("FRP configuration material was written to the journal")
	}
}

func TestAutoFRPLogDoesNotClaimTunnelIsVerified(t *testing.T) {
	t.Setenv("TY_GATEWAY_TEST_FRPC_HELPER", "1")
	t.Setenv("TY_GATEWAY_TEST_FRPC_MODE", "run")
	var logs bytes.Buffer
	state := credentialState{DeviceID: "device-test", DeviceSecret: strings.Repeat("a", 64)}
	manager := newAutoFRPManager(filepath.Join(t.TempDir(), "frpc-auto.toml"), os.Args[0])
	t.Cleanup(func() { _ = manager.Apply(context.Background(), state, nil) })
	a := &agent{autoFRP: manager, state: state, logger: log.New(&logs, "", 0)}
	a.reconcileAutoFRP(context.Background(), &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7001, RemotePort: 22000, TLSCA: testAutoFRPCA(t)})

	if got := logs.String(); !strings.Contains(got, "client process started") || !strings.Contains(got, "reachability remains unverified") || strings.Contains(got, "tunnel connected") {
		t.Fatalf("FRP process startup must not be reported as a verified tunnel: %q", got)
	}
}

func TestAutoFRPManagerRestoresWorkingConfigWhenReplacementFails(t *testing.T) {
	t.Setenv("TY_GATEWAY_TEST_FRPC_HELPER", "1")
	t.Setenv("TY_GATEWAY_TEST_FRPC_MODE", "run")
	t.Setenv("TY_GATEWAY_TEST_FRPC_FAIL_HOST", "new.example.test")
	state := credentialState{DeviceID: "device-test", DeviceSecret: strings.Repeat("c", 64)}
	oldConfig := &model.AutoFRPConfig{Host: "old.example.test", ControlPort: 7001, RemotePort: 22000, TLSCA: testAutoFRPCA(t)}
	newConfig := &model.AutoFRPConfig{Host: "new.example.test", ControlPort: 7001, RemotePort: 22000, TLSCA: testAutoFRPCA(t)}
	manager := newAutoFRPManager(filepath.Join(t.TempDir(), "frpc-auto.toml"), os.Args[0])
	t.Cleanup(func() { _ = manager.Apply(context.Background(), state, nil) })

	if err := manager.Apply(context.Background(), state, oldConfig); err != nil {
		t.Fatalf("initial FRP apply: %v", err)
	}
	oldFile, err := os.ReadFile(manager.configPath)
	if err != nil {
		t.Fatal(err)
	}
	oldCA, err := os.ReadFile(manager.caPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), state, newConfig); err == nil {
		t.Fatal("FRP replacement succeeded although its client failed to start")
	}
	if manager.cmd == nil {
		t.Fatal("last known-good FRP client was not restarted")
	}
	gotFile, err := os.ReadFile(manager.configPath)
	if err != nil || string(gotFile) != string(oldFile) {
		t.Fatalf("last known-good FRP configuration was not restored: %v", err)
	}
	gotCA, err := os.ReadFile(manager.caPath)
	if err != nil || string(gotCA) != string(oldCA) {
		t.Fatalf("last known-good FRP CA was not restored: %v", err)
	}
}

func testAutoFRPCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
