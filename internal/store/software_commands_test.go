package store

import (
	"context"
	"errors"
	"testing"

	"tygateway/internal/model"
)

func TestOnlyOneSoftwareMaintenanceCommandCanBeInFlight(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	d, _, err := s.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:89"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "software_update", Payload: "pilot:0.8.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "software_rollback", Payload: "0.7.3"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("parallel rollback not rejected: %v", err)
	}
	if _, err := s.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "software_update", Payload: "pilot:0.8.0"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate upgrade not rejected: %v", err)
	}
	claimed, err := s.PollCommands(ctx, d.ID)
	if err != nil || len(claimed) != 1 || claimed[0].ID != first.ID {
		t.Fatalf("claimed=%#v %v", claimed, err)
	}
	if err := s.AckCommand(ctx, d.ID, first.ID, "failed"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueCommand(ctx, model.Command{DeviceID: d.ID, Command: "software_rollback", Payload: "0.7.3"}); err != nil {
		t.Fatalf("later recovery command rejected: %v", err)
	}
}
