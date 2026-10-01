package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"tygateway/internal/model"
)

func TestDeactivateDeviceLifecycleAndScope(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	sub, err := s.CreateSubscription(ctx, "source", "test", []byte("encrypted-secret"))
	if err != nil {
		t.Fatal(err)
	}
	const mac = "02:00:00:00:90:01"
	if _, err := s.PrepareMACDeviceEnrollment(ctx, mac, "original", "gfw_precise", ""); err != nil {
		t.Fatal(err)
	}
	oldSecret := strings.Repeat("a", 64)
	d, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: oldSecret})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BindSubscription(ctx, d.ID, sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateDevice(ctx, d.ID, model.DeviceEnabled, "latest baseline", "managed_meta"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateIdentity(ctx, d.ID, "old user name", "old@example.test", sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AllocateRescueSSHPort(ctx, d.ID, 22000, 22002); err != nil {
		t.Fatal(err)
	}
	_, _, _ = s.RotateCustomerAccess(ctx, d.ID)
	_, _ = s.SaveCustomerRule(ctx, model.Rule{DeviceID: d.ID, MatchType: "domain", MatchValue: "example.test", Action: "DIRECT"})
	_, _ = s.CreateRule(ctx, model.Rule{DeviceID: d.ID, Source: "admin", MatchType: "domain", MatchValue: "private.test", Action: "PROXY"})
	global, _ := s.CreateRule(ctx, model.Rule{Source: "admin", MatchType: "domain", MatchValue: "shared.test", Action: "DIRECT"})
	_, _ = s.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "report_status"})
	if err := s.SetCustomerNodePreference(ctx, d.ID, "ai", "@direct"); err != nil {
		t.Fatal(err)
	}
	other, _, _ := s.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:90:02"})
	_, _ = s.AllocateRescueSSHPort(ctx, other.ID, 22000, 22002)
	if len(s.rules) != 3 || len(s.commands) != 1 || s.customerNodePrefs[d.ID]["ai"] != "@direct" || s.customerSecrets[d.ID] == "" {
		t.Fatal("test device configuration fixture incomplete")
	}
	d, _ = s.GetDevice(ctx, d.ID)
	for _, in := range []struct {
		version int64
		mac     string
	}{{d.ConfigVersion - 1, mac}, {d.ConfigVersion, other.MAC}} {
		if _, err := s.DeactivateDevice(ctx, d.ID, in.version, in.mac); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale/wrong MAC: %v", err)
		}
		if _, err := s.GetDeviceAuth(ctx, d.ID); err != nil {
			t.Fatal("rejected reset changed identity")
		}
	}
	record, err := s.DeactivateDevice(ctx, d.ID, d.ConfigVersion, mac)
	if err != nil {
		t.Fatal(err)
	}
	if record.ClaimedAt != nil || record.DeviceID != "" || record.ClaimMode != "mac" || record.Note != "latest baseline" || record.Profile != "managed_meta" || record.SubscriptionID != sub.ID || time.Until(record.ExpiresAt) < 29*24*time.Hour {
		t.Fatalf("incorrect baseline/claim reset: %#v", record)
	}
	if _, err := s.GetDeviceAuth(ctx, d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("old auth remains")
	}
	if _, err := s.GetCustomerAuthBySerial(ctx, d.Serial); !errors.Is(err, ErrNotFound) {
		t.Fatal("old customer auth remains")
	}
	if _, ok := s.customerNodePrefs[d.ID]; ok {
		t.Fatal("preferences remain")
	}
	for _, rule := range s.rules {
		if rule.DeviceID == d.ID {
			t.Fatal("device rule remains")
		}
	}
	for _, command := range s.commands {
		if command.DeviceID == d.ID {
			t.Fatal("device command remains")
		}
	}
	if _, ok := s.rules[global.ID]; !ok {
		t.Fatal("global rule removed")
	}
	if stored, err := s.GetDevice(ctx, other.ID); err != nil || stored.RescueSSHPort != 22001 {
		t.Fatal("other device changed")
	}
	if ciphertext, _ := s.GetSubscriptionCiphertext(ctx, sub.ID); string(ciphertext) != "encrypted-secret" {
		t.Fatal("shared subscription changed")
	}
	if _, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: oldSecret}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatal("revoked pending claim reactivated device")
	}
	fresh, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: strings.Repeat("b", 64)})
	if err != nil || fresh.ID == d.ID || fresh.DeviceNumber <= other.DeviceNumber || fresh.Name != "" || fresh.Email != "" || fresh.RescueSSHPort != 0 || fresh.Profile != record.Profile || fresh.SubscriptionID != sub.ID {
		t.Fatalf("fresh claim: %#v %v", fresh, err)
	}
	if port, err := s.AllocateRescueSSHPort(ctx, fresh.ID, 22000, 22002); err != nil || port != 22000 {
		t.Fatalf("released lowest port: %d %v", port, err)
	}
	if _, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: oldSecret}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatal("old key accepted after fresh claim")
	}
	// A stale drawer must never deactivate the replacement record with the same MAC.
	if _, err := s.DeactivateDevice(ctx, d.ID, d.ConfigVersion, mac); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repeated old request: %v", err)
	}
	if _, err := s.GetDeviceAuth(ctx, fresh.ID); err != nil {
		t.Fatal("replacement lost after repeated old request")
	}
}

func TestDeactivateDeviceConcurrentRequests(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	const mac = "02:00:00:00:91:01"
	_, _ = s.PrepareMACDeviceEnrollment(ctx, mac, "", "", "")
	d, _, _ := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: mac, DeviceSecret: strings.Repeat("a", 64)})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.DeactivateDevice(ctx, d.ID, d.ConfigVersion, mac); results <- err }()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrNotFound) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("reset committed %d times", winners)
	}
}
