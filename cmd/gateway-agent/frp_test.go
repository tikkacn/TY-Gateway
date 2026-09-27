package main

import (
	"strings"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/frpauth"
	"tygateway/internal/model"
)

func TestRenderAutoFRPConfigUsesDeviceScopedCredentialAndSeparatePort(t *testing.T) {
	state := credentialState{DeviceID: "device-abcd", DeviceSecret: strings.Repeat("a", 64)}
	config := &model.AutoFRPConfig{Host: "frp.example.test", ControlPort: 7002, RemotePort: 22017}
	text, gotCredential, err := renderAutoFRPConfig(state, config, "/var/lib/ty-gateway/frp-auto-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	wantCredential, err := frpauth.Credential(auth.SecretHash(state.DeviceSecret), state.DeviceID, config.RemotePort)
	if err != nil || gotCredential != wantCredential {
		t.Fatalf("FRP credential derivation mismatch: %v", err)
	}
	for _, expected := range []string{
		"serverPort = 7002",
		"remotePort = 22017",
		"transport.tls.trustedCaFile",
		"metadatas.device_id = \"device-abcd\"",
		"metadatas.rescue_key = \"" + wantCredential + "\"",
		"name = \"device-abcd.ssh-rescue\"",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("generated FRPC config missing %q", expected)
		}
	}
	if strings.Contains(text, "22000") || strings.Contains(text, "auth.token") {
		t.Fatal("generated FRPC config overlaps the legacy rescue port or embeds a shared token")
	}
}

func TestRenderAutoFRPConfigRejectsUnsafeOrLegacyInputs(t *testing.T) {
	state := credentialState{DeviceID: "device-abcd", DeviceSecret: strings.Repeat("a", 64)}
	for _, config := range []*model.AutoFRPConfig{
		{Host: "frp.example.test\nloginFailExit = false", ControlPort: 7002, RemotePort: 22017},
		{Host: "frp.example.test", ControlPort: 7001, RemotePort: 22000},
		{Host: "frp.example.test", ControlPort: 7002, RemotePort: 0},
	} {
		if _, _, err := renderAutoFRPConfig(state, config, "/tmp/ca.pem"); err == nil {
			t.Fatalf("unsafe automatic FRP config was accepted: %#v", config)
		}
	}
}
