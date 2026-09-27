package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestConcurrentFleetAndCommandBoundary(t *testing.T) {
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d, secret, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: fmt.Sprintf("02:00:00:00:00:%02X", i)})
			if err != nil {
				t.Error(err)
				return
			}
			for n := 0; n < 4; n++ {
				w := httptest.NewRecorder()
				srv.ServeHTTP(w, signedRequest("POST", "/api/v1/device/"+d.ID+"/heartbeat", []byte(`{"status":"ok"}`), d.ID, auth.SecretHash(secret)))
				if w.Code != 200 {
					t.Errorf("heartbeat status %d", w.Code)
				}
			}
		}(i)
	}
	wg.Wait()
	devices, err := st.ListDevices(context.Background(), srv.OfflineAfter)
	if err != nil || len(devices) != 100 {
		t.Fatal("fleet incomplete")
	}
	for _, d := range devices {
		if !d.Online {
			t.Fatal("unexpected offline device")
		}
	}
	req := httptest.NewRequest("GET", "/api/v1/admin/devices", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("unprotected admin")
	}
	req = httptest.NewRequest("POST", "/api/v1/admin/rules", bytes.NewBufferString(`{"match_type":"bad","match_value":"example.com","action":"DIRECT"}`))
	req.Header.Set("X-TY-Admin-Token", "admin-test")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatal("invalid rule accepted")
	}
}
