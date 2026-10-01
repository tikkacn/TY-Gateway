package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStockHTTPSPortMigrationPreservesDeviceIdentity(t *testing.T) {
	a := &agent{stateDir: t.TempDir(), server: "https://oec.188811.xyz:8443", state: credentialState{Server: "https://oec.188811.xyz", DeviceID: "device-1", DeviceSecret: "original-secret", Serial: "30A61209E431", MAC: "30A61209E431", RescuePort: 22000}}
	before := a.state
	if err := a.saveState(); err != nil {
		t.Fatal(err)
	}
	if err := a.reconcileCredentialServer(); err != nil {
		t.Fatal(err)
	}
	want := before
	want.Server = a.server
	if !reflect.DeepEqual(a.state, want) {
		t.Fatal("HTTPS migration changed device identity or rescue assignment")
	}
	restarted := &agent{stateDir: a.stateDir}
	if err := restarted.loadState(); err != nil || !reflect.DeepEqual(restarted.state, want) {
		t.Fatalf("migration not durable: %v", err)
	}
	if err := a.reconcileCredentialServer(); err != nil {
		t.Fatal("migration was not idempotent", err)
	}
}

func TestStockHTTPSPortMigrationRefusesOtherDestinations(t *testing.T) {
	for _, target := range []string{"https://other.example:8443", "http://oec.188811.xyz:8443", "https://oec.188811.xyz:9443", "https://oec.188811.xyz:8443/other"} {
		a := &agent{stateDir: t.TempDir(), server: target, state: credentialState{Server: "https://oec.188811.xyz", DeviceID: "device-1", DeviceSecret: "original-secret"}}
		before := a.state
		if err := a.reconcileCredentialServer(); err == nil || !reflect.DeepEqual(a.state, before) {
			t.Fatalf("unexpected credential migration to %s", target)
		}
	}
	a := &agent{stateDir: t.TempDir(), server: "https://oec.188811.xyz", state: credentialState{Server: "https://oec.188811.xyz:8443"}}
	if err := a.reconcileCredentialServer(); err == nil {
		t.Fatal("reverse migration silently accepted")
	}
}

func TestStockHTTPSPortMigrationRetainsStateOnWriteFailure(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &agent{stateDir: blocker, server: "https://oec.188811.xyz:8443", state: credentialState{Server: "https://oec.188811.xyz", DeviceID: "device-1", DeviceSecret: "original-secret"}}
	before := a.state
	if err := a.reconcileCredentialServer(); err == nil || !reflect.DeepEqual(a.state, before) {
		t.Fatal("failed migration altered in-memory identity")
	}
}
