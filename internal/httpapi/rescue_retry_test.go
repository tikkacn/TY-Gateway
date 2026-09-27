package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

type failOnceRescueStore struct {
	store.Store
	fail bool
}

type failingDeviceReadStore struct{ store.Store }

func (s *failingDeviceReadStore) GetDevice(context.Context, string) (model.Device, error) {
	return model.Device{}, errors.New("temporary database failure")
}

func (s *failOnceRescueStore) AllocateRescueSSHPort(ctx context.Context, id string, start, end int) (int, error) {
	if s.fail {
		s.fail = false
		return 0, errors.New("temporary database failure")
	}
	return s.Store.AllocateRescueSSHPort(ctx, id, start, end)
}

func TestRescuePortSkipsLiveListenerAndNeverReassignsOnRetry(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	busy := listener.Addr().(*net.TCPAddr).Port
	if busy > 65531 {
		t.Skip("ephemeral port is too near the end of the TCP range")
	}
	st := store.NewMemoryStore()
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:66:01"})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.Rescue = &model.RescueConfig{Host: "127.0.0.1"}
	srv.FRPS.RemotePortStart, srv.FRPS.RemotePortEnd = busy, busy+4
	assigned, err := srv.allocateRescuePort(context.Background(), d.ID)
	if err != nil || assigned <= busy {
		t.Fatalf("assigned=%d err=%v; busy port=%d", assigned, err, busy)
	}
	retry, err := srv.allocateRescuePort(context.Background(), d.ID)
	if err != nil || retry != assigned {
		t.Fatalf("retry moved sticky port from %d to %d: %v", assigned, retry, err)
	}
	stored, err := st.GetDevice(context.Background(), d.ID)
	if err != nil || stored.RescueSSHPort != assigned {
		t.Fatalf("stored port=%d err=%v", stored.RescueSSHPort, err)
	}
}

func TestFailedRescueAllocationRetriesOnNextDeviceConfig(t *testing.T) {
	st := store.NewMemoryStore()
	_, code, err := st.PrepareDeviceEnrollment(context.Background(), "02:00:00:00:66:02", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	d, secret, err := st.RegisterApprovedDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:66:02", ActivationCode: code, DeviceSecret: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	if port > 65531 {
		t.Skip("ephemeral port is too near the end of the TCP range")
	}
	flaky := &failOnceRescueStore{Store: st, fail: true}
	srv := NewServer(flaky, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	srv.Rescue = &model.RescueConfig{Host: "127.0.0.1", Port: 7001}
	srv.FRPS.RemotePortStart, srv.FRPS.RemotePortEnd = port, port+4
	if _, err := srv.allocateRescuePort(context.Background(), d.ID); err == nil {
		t.Fatal("first allocation should fail")
	}
	r := signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil, d.ID, auth.SecretHash(secret))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("config status=%d body=%s", w.Code, w.Body.String())
	}
	var config model.DeviceConfig
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil || config.Rescue == nil || config.Rescue.RemotePort < port {
		t.Fatalf("config rescue port was not retried: %s, %v", w.Body.String(), err)
	}
}

func TestConfigDoesNotAllocatePortForLegacyUnassignedDevice(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	d, secret, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:66:04"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = st.UpdateDevice(ctx, d.ID, model.DeviceEnabled, "", "")
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	srv.Rescue = &model.RescueConfig{Host: "127.0.0.1", Port: 7001}
	r := signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil, d.ID, auth.SecretHash(secret))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("existing device config status=%d body=%s", w.Code, w.Body.String())
	}
	stored, err := st.GetDevice(ctx, d.ID)
	if err != nil || stored.RescueSSHPort != 0 {
		t.Fatalf("legacy device was assigned a new port: %d %v", stored.RescueSSHPort, err)
	}
}

func TestTransientConfigStorageFailureIsNotReportedAsMissingDevice(t *testing.T) {
	st := store.NewMemoryStore()
	d, secret, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:66:03"})
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(&failingDeviceReadStore{Store: st}, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	r := signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil, d.ID, auth.SecretHash(secret))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("temporary storage failure status=%d; want 503", w.Code)
	}
}
