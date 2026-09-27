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

func TestMemoryEnrollmentReservationAndRevocation(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	record, code, err := s.PrepareDeviceEnrollment(ctx, "02:00:00:00:80:01", "test", "", "")
	if err != nil || code == "" || record.MAC != "020000008001" {
		t.Fatalf("prepare failed: %#v %v", record, err)
	}
	if _, _, err := s.PrepareDeviceEnrollment(ctx, record.MAC, "duplicate", "", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate preparation = %v", err)
	}
	if err := s.RevokeDeviceEnrollment(ctx, record.MAC); err != nil {
		t.Fatal(err)
	}
	_, code, err = s.PrepareDeviceEnrollment(ctx, record.MAC, "replacement", "", "")
	if err != nil {
		t.Fatal(err)
	}
	deviceSecret := strings.Repeat("a", 64)
	d, _, err := s.RegisterApprovedDevice(ctx, model.RegisterDeviceInput{MAC: record.MAC, ActivationCode: code, DeviceSecret: deviceSecret})
	if err != nil || d.State != model.DeviceEnabled || d.Note != "replacement" {
		t.Fatalf("claim failed: %#v %v", d, err)
	}
	if err := s.RevokeDeviceEnrollment(ctx, record.MAC); !errors.Is(err, ErrConflict) {
		t.Fatalf("claimed record should not be revocable: %v", err)
	}
	if retry, _, err := s.RegisterApprovedDevice(ctx, model.RegisterDeviceInput{MAC: record.MAC, ActivationCode: code, DeviceSecret: deviceSecret}); err != nil || retry.ID != d.ID {
		t.Fatalf("idempotent registration retry failed: %#v %v", retry, err)
	}
	if _, _, err := s.RegisterApprovedDevice(ctx, model.RegisterDeviceInput{MAC: record.MAC, ActivationCode: code, DeviceSecret: strings.Repeat("b", 64)}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("different secret was accepted: %v", err)
	}
}

func TestPreparedSubscriptionCannotBeStolenByManualBinding(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	sub, err := s.CreateSubscription(ctx, "test", "test", []byte("encrypted"))
	if err != nil {
		t.Fatal(err)
	}
	d, _, err := s.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:81:01"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.PrepareDeviceEnrollment(ctx, "02:00:00:00:81:02", "", "", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.BindSubscription(ctx, d.ID, sub.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("manual binding stole prepared subscription: %v", err)
	}
	if _, err := s.UpdateIdentity(ctx, d.ID, "", "", sub.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("identity update stole prepared subscription: %v", err)
	}
	if err := s.RevokeDeviceEnrollment(ctx, "02:00:00:00:81:02"); err != nil {
		t.Fatal(err)
	}
	if err := s.BindSubscription(ctx, d.ID, sub.ID); err != nil {
		t.Fatalf("revoked reservation still blocked binding: %v", err)
	}
}

func TestDeletingSubscriptionClearsPreparedBinding(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	sub, err := s.CreateSubscription(ctx, "test", "test", []byte("encrypted"))
	if err != nil {
		t.Fatal(err)
	}
	_, code, err := s.PrepareDeviceEnrollment(ctx, "02:00:00:00:82:01", "", "", sub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSubscription(ctx, sub.ID); err != nil {
		t.Fatal(err)
	}
	d, _, err := s.RegisterApprovedDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:82:01", ActivationCode: code, DeviceSecret: strings.Repeat("a", 64)})
	if err != nil || d.SubscriptionID != "" {
		t.Fatalf("activation after subscription removal failed: %#v %v", d, err)
	}
}

func TestExpiredActivationCanBeRevokedAndRegenerated(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	record, code, err := s.PrepareDeviceEnrollment(ctx, "02:00:00:00:83:01", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	expired := s.deviceEnrollments[record.MAC]
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	s.deviceEnrollments[record.MAC] = expired
	s.mu.Unlock()
	if _, _, err := s.RegisterApprovedDevice(ctx, model.RegisterDeviceInput{MAC: record.MAC, ActivationCode: code, DeviceSecret: strings.Repeat("a", 64)}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("expired activation was accepted: %v", err)
	}
	if err := s.RevokeDeviceEnrollment(ctx, record.MAC); err != nil {
		t.Fatal(err)
	}
	if _, replacement, err := s.PrepareDeviceEnrollment(ctx, record.MAC, "", "", ""); err != nil || replacement == code {
		t.Fatalf("expired activation could not be rotated: %v", err)
	}
}

func TestMACClaimIsFirstWriterWinsAndRetrySafe(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	record, err := s.PrepareMACDeviceEnrollment(ctx, "02:00:00:00:84:01", "pilot", "", "")
	if err != nil || record.ClaimMode != "mac" {
		t.Fatalf("MAC preparation failed: %#v %v", record, err)
	}
	secrets := []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	type claimResult struct {
		device model.Device
		secret string
		err    error
	}
	results := make(chan claimResult, len(secrets))
	var wg sync.WaitGroup
	for _, secret := range secrets {
		wg.Add(1)
		go func(secret string) {
			defer wg.Done()
			device, _, claimErr := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: record.MAC, DeviceSecret: secret})
			results <- claimResult{device: device, secret: secret, err: claimErr}
		}(secret)
	}
	wg.Wait()
	close(results)
	successes := 0
	var winner claimResult
	for result := range results {
		if result.err == nil {
			successes++
			winner = result
		}
	}
	if successes != 1 {
		t.Fatalf("first claim must win exactly once, got %d successful competing claims", successes)
	}
	if retry, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: record.MAC, DeviceSecret: winner.secret}); err != nil || retry.ID != winner.device.ID {
		t.Fatalf("same-secret retry must return the claimed identity: %#v %v", retry, err)
	}
	if _, _, err := s.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: record.MAC, DeviceSecret: strings.Repeat("c", 64)}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("different claimant secret was accepted: %v", err)
	}
}
