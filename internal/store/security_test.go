package store

import (
	"context"
	"testing"
	"tygateway/internal/model"
)

func TestCommandOwnershipAndLKG(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	s.devices["owner"] = model.Device{ID: "owner"}
	c, _ := s.EnqueueCommand(ctx, model.Command{DeviceID: "owner", Command: "report_status"})
	s.PollCommands(ctx, "owner")
	if s.AckCommand(ctx, "attacker", c.ID, "ok") == nil {
		t.Fatal("cross-device ack accepted")
	}
	if err := s.AckCommand(ctx, "owner", c.ID, "ok"); err != nil {
		t.Fatal(err)
	}
	sub, _ := s.CreateSubscription(ctx, "test", "test", nil)
	s.UpdateSubscriptionStatus(ctx, sub.ID, "ok", 12)
	before, _ := s.ListSubscriptions(ctx)
	s.UpdateSubscriptionStatus(ctx, sub.ID, "error", -1)
	after, _ := s.ListSubscriptions(ctx)
	if after[0].NodeCount != 12 || !after[0].LastRefresh.Equal(*before[0].LastRefresh) {
		t.Fatal("failure destroyed last good metadata")
	}
}
