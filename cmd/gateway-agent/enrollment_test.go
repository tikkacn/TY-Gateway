package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAgentActivationFileBindsToInterfaceMAC(t *testing.T) {
	dir := t.TempDir()
	a := &agent{stateDir: dir}
	if activation, err := a.readActivation("AABBCCDDEE01"); err != nil || activation.ActivationCode != "" {
		t.Fatalf("missing activation should be handled by Cloud: %#v %v", activation, err)
	}
	code := strings.Repeat("a", 64)
	data, _ := json.Marshal(activationFile{MAC: "AABBCCDDEE01", ActivationCode: code})
	if err := os.WriteFile(filepath.Join(dir, "activation.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.readActivation("AABBCCDDEE02"); err == nil {
		t.Fatal("wrong device MAC accepted")
	}
	if got, err := a.readActivation("AABBCCDDEE01"); err != nil || got.ActivationCode != code {
		t.Fatalf("valid activation file rejected: %#v %v", got, err)
	}
}

func TestAgentPersistsRandomPendingIdentityForRetry(t *testing.T) {
	dir := t.TempDir()
	a := &agent{stateDir: dir}
	first, err := a.loadOrCreatePendingIdentity("AABBCCDDEE11")
	if err != nil || !validSecret(first) {
		t.Fatalf("could not create pending device identity: %v", err)
	}
	second, err := a.loadOrCreatePendingIdentity("AABBCCDDEE11")
	if err != nil || second != first {
		t.Fatalf("retry must reuse the durable identity: %v", err)
	}
	if _, err := a.loadOrCreatePendingIdentity("AABBCCDDEE12"); err == nil {
		t.Fatal("pending identity was silently reused for a different interface MAC")
	}
	info, err := os.Stat(filepath.Join(dir, "pending-enrollment.json"))
	if err != nil {
		t.Fatalf("pending identity file is missing: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("pending identity file has permissions %v, want 0600", info.Mode().Perm())
	}
}

func TestAgentRescuePortPersistsWithoutLosingCredentials(t *testing.T) {
	dir := t.TempDir()
	a := &agent{stateDir: dir, state: credentialState{Server: "https://example.invalid", DeviceID: "device", DeviceSecret: strings.Repeat("a", 64), Serial: "AABBCCDDEE01", MAC: "AABBCCDDEE01"}}
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	if err := a.persistRescuePort(22001); err != nil {
		t.Fatal(err)
	}
	loaded := &agent{stateDir: dir}
	if err := loaded.loadState(); err != nil {
		t.Fatal(err)
	}
	if got := loaded.stateValue(); got.RescuePort != 22001 || got.DeviceSecret != strings.Repeat("a", 64) {
		t.Fatalf("port update damaged credentials: %#v", got)
	}
	if err := loaded.persistRescuePort(0); err != nil {
		t.Fatal(err)
	}
	if got := loaded.stateValue(); got.RescuePort != 0 || got.DeviceSecret != strings.Repeat("a", 64) {
		t.Fatalf("port removal damaged credentials: %#v", got)
	}
}

func TestAgentRemovesConsumedActivationFile(t *testing.T) {
	dir := t.TempDir()
	a := &agent{stateDir: dir}
	path := filepath.Join(dir, "activation.json")
	if err := os.WriteFile(path, []byte(`{"mac":"AABBCCDDEE01"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := a.cleanupConsumedActivation(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("used activation file remains: %v", err)
	}
	if err := a.cleanupConsumedActivation(); err != nil {
		t.Fatalf("cleanup should be retry-safe: %v", err)
	}
}
