package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/frpauth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestFRPRosterOnlyIncludesApprovedEnabledAssignedDevices(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	legacy, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:71:01"})
	if err != nil || st.SetRescueSSHPort(ctx, legacy.ID, 22000) != nil {
		t.Fatal("legacy setup failed")
	}
	_, err = st.PrepareMACDeviceEnrollment(ctx, "02:00:00:00:71:02", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	deviceSecret := strings.Repeat("1", 64)
	d, _, err := st.RegisterMACClaim(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:71:02", DeviceSecret: deviceSecret})
	if err != nil || st.SetRescueSSHPort(ctx, d.ID, 22001) != nil {
		t.Fatal("approved setup failed")
	}
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.FRPRosterToken = strings.Repeat("r", 48)
	srv.FRPRosterPortStart, srv.FRPRosterPortEnd = 22000, 22999
	get := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/frp/roster", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	if w := get("admin-test"); w.Code != http.StatusUnauthorized {
		t.Fatalf("admin token could access machine feed: %d", w.Code)
	}
	w := get(srv.FRPRosterToken)
	if w.Code != http.StatusOK {
		t.Fatalf("feed: %d %s", w.Code, w.Body.String())
	}
	var roster frpauth.Roster
	if err := json.Unmarshal(w.Body.Bytes(), &roster); err != nil || len(roster.Entries) != 1 || roster.Entries[0].DeviceID != d.ID || roster.Entries[0].Port != 22001 {
		t.Fatalf("unexpected roster: %s %v", w.Body.String(), err)
	}
	credential, _ := frpauth.Credential(auth.SecretHash(deviceSecret), d.ID, 22001)
	if _, ok := roster.Authorize(d.ID, credential); !ok || strings.Contains(w.Body.String(), deviceSecret) || strings.Contains(w.Body.String(), auth.SecretHash(deviceSecret)) {
		t.Fatal("roster credential failed or exposed device/activation secret")
	}
	if _, err := st.UpdateDevice(ctx, d.ID, model.DeviceDisabled, "", ""); err != nil {
		t.Fatal(err)
	}
	w = get(srv.FRPRosterToken)
	if err := json.Unmarshal(w.Body.Bytes(), &roster); err != nil || len(roster.Entries) != 0 {
		t.Fatalf("disabled device remains authorized: %s %v", w.Body.String(), err)
	}
}
