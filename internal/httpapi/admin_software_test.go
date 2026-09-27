package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestAdminSoftwareQueueRequiresExactApprovalAndReportsDeviceAck(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-secret", []byte("0123456789abcdef0123456789abcdef"))
	device, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:88", AgentVersion: "0.8.0"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateDevice(ctx, device.ID, model.DeviceEnabled, "", device.Profile); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/admin/devices/software"
	request := func(method, target, body string, auth bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		if auth {
			r.Header.Set("X-TY-Admin-Token", "admin-secret")
		}
		srv.ServeHTTP(w, r)
		return w
	}
	valid := `{"device_id":"` + device.ID + `","operation":"update","channel":"pilot","version":"0.8.0","confirm":"UPDATE:0.8.0"}`
	if w := request(http.MethodPost, path, valid, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized command accepted: %d", w.Code)
	}
	for _, bad := range []string{
		strings.Replace(valid, `"confirm":"UPDATE:0.8.0"`, `"confirm":"no"`, 1),
		strings.Replace(valid, `"version":"0.8.0"`, `"version":"0.8.0;evil"`, 1),
		strings.Replace(valid, `"channel":"pilot"`, `"channel":"https://example.test"`, 1),
		strings.TrimSuffix(valid, "}") + `,"url":"https://example.test"}`,
	} {
		if w := request(http.MethodPost, path, bad, true); w.Code != http.StatusBadRequest {
			t.Fatalf("unsafe command accepted: %d %s", w.Code, w.Body.String())
		}
	}
	queued := request(http.MethodPost, path, valid, true)
	if queued.Code != http.StatusAccepted || !strings.Contains(queued.Body.String(), `"software_update"`) || !strings.Contains(queued.Body.String(), `"queued"`) {
		t.Fatalf("update not queued: %d %s", queued.Code, queued.Body.String())
	}
	if w := request(http.MethodPost, path, valid, true); w.Code != http.StatusConflict {
		t.Fatalf("duplicate in-flight command accepted: %d", w.Code)
	}
	claimed, err := st.PollCommands(ctx, device.ID)
	if err != nil || len(claimed) != 1 || claimed[0].Payload != "pilot:0.8.0" {
		t.Fatalf("device command=%#v %v", claimed, err)
	}
	status := request(http.MethodGet, path+"?device_id="+device.ID, "", true)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"status":"claimed"`) {
		t.Fatalf("claimed status unavailable: %d %s", status.Code, status.Body.String())
	}
	if err := st.AckCommand(ctx, device.ID, claimed[0].ID, "ok"); err != nil {
		t.Fatal(err)
	}
	status = request(http.MethodGet, path+"?device_id="+device.ID, "", true)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"status":"ok"`) {
		t.Fatalf("confirmed status unavailable: %d %s", status.Code, status.Body.String())
	}
	rollback := `{"device_id":"` + device.ID + `","operation":"rollback","version":"0.8.0","confirm":"ROLLBACK:0.8.0"}`
	if w := request(http.MethodPost, path, rollback, true); w.Code != http.StatusAccepted || !strings.Contains(w.Body.String(), `"software_rollback"`) {
		t.Fatalf("rollback not queued: %d %s", w.Code, w.Body.String())
	}
}

func TestRemoteSoftwareRequiresNewAgent(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-secret", []byte("0123456789abcdef0123456789abcdef"))
	device, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:89", AgentVersion: "0.7.3"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateDevice(ctx, device.ID, model.DeviceEnabled, "", device.Profile); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/admin/devices/software"
	get := httptest.NewRequest(http.MethodGet, path+"?device_id="+device.ID, nil)
	get.Header.Set("X-TY-Admin-Token", "admin-secret")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, get)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"remote_supported":false`) {
		t.Fatalf("legacy Agent was advertised as supported: %d %s", w.Code, w.Body.String())
	}
	post := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"device_id":"`+device.ID+`","operation":"update","channel":"pilot","version":"0.8.0","confirm":"UPDATE:0.8.0"}`))
	post.Header.Set("X-TY-Admin-Token", "admin-secret")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, post)
	if w.Code != http.StatusConflict {
		t.Fatalf("legacy Agent update command was queued: %d %s", w.Code, w.Body.String())
	}
	for _, value := range []struct {
		version string
		want    bool
	}{
		{"", false}, {"0.7.3", false}, {"0.8.0", true}, {"0.9.1", true}, {"1.0.0", true}, {"0.8.0-test", false},
	} {
		if got := remoteSoftwareSupported(value.version); got != value.want {
			t.Errorf("remoteSoftwareSupported(%q)=%v, want %v", value.version, got, value.want)
		}
	}
}
