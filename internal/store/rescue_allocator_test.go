package store

import (
	"context"
	"sync"
	"testing"

	"tygateway/internal/model"
)

func TestMemoryRescueAllocatorUsesLowestFreePortAndIsSticky(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	first, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:10:01"})
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:10:02"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRescueSSHPort(ctx, first.ID, 22000); err != nil {
		t.Fatal(err)
	}
	port, err := st.AllocateRescueSSHPort(ctx, second.ID, 22000, 22002)
	if err != nil || port != 22001 {
		t.Fatalf("allocated port = %d, err = %v; want lowest free 22001", port, err)
	}
	again, err := st.AllocateRescueSSHPort(ctx, second.ID, 22000, 22002)
	if err != nil || again != 22001 {
		t.Fatalf("sticky port = %d, err = %v; want 22001", again, err)
	}
}

func TestMemoryRescueAllocatorClaimsDistinctPortsConcurrently(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	const devices = 8
	ids := make([]string, 0, devices)
	for i := 0; i < devices; i++ {
		d, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:20:" + formatTestMACByte(i)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, d.ID)
	}
	ports := make(chan int, devices)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(deviceID string) {
			defer wg.Done()
			port, err := st.AllocateRescueSSHPort(ctx, deviceID, 22100, 22199)
			if err != nil {
				t.Errorf("allocate %s: %v", deviceID, err)
				return
			}
			ports <- port
		}(id)
	}
	wg.Wait()
	close(ports)
	seen := make(map[int]struct{}, devices)
	for port := range ports {
		if _, exists := seen[port]; exists {
			t.Fatalf("duplicate allocated port %d", port)
		}
		seen[port] = struct{}{}
	}
	if len(seen) != devices {
		t.Fatalf("allocated %d ports, want %d", len(seen), devices)
	}
}

func formatTestMACByte(value int) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[(value>>4)&0xf], digits[value&0xf]})
}
