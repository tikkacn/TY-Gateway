package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestAdminSupportResetLeavesRegistrationAndBaseline(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:97"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetRescueSSHPort(ctx, d.ID, 22001); err != nil {
		t.Fatal(err)
	}
	base, err := st.CreateRule(ctx, model.Rule{DeviceID: d.ID, Source: "admin", SourceType: "admin", MatchType: "domain_suffix", MatchValue: "example.org", Action: "PROXY"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveCustomerRule(ctx, model.Rule{DeviceID: d.ID, MatchType: "domain_suffix", MatchValue: "example.org", Action: "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	d, err = st.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"device_id":"` + d.ID + `","expected_version":` + strconv.FormatInt(d.ConfigVersion, 10) + `,"confirm":"RESET_CUSTOMER_SETTINGS"}`
	path := "/api/v1/admin/devices/reset-customer-settings"
	send := func(authenticated bool, requestBody string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(requestBody))
		if authenticated {
			r.Header.Set("X-TY-Admin-Token", "admin")
		}
		srv.ServeHTTP(w, r)
		return w
	}
	if w := send(false, body); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized reset=%d", w.Code)
	}
	staleBody := strings.Replace(body, `"expected_version":`+strconv.FormatInt(d.ConfigVersion, 10), `"expected_version":`+strconv.FormatInt(d.ConfigVersion-1, 10), 1)
	if w := send(true, staleBody); w.Code != http.StatusConflict {
		t.Fatalf("stale reset=%d %s", w.Code, w.Body.String())
	}
	w := send(true, body)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"reload_queued":true`) {
		t.Fatalf("support reset=%d %s", w.Code, w.Body.String())
	}
	commands, err := st.PollCommands(ctx, d.ID)
	if err != nil || len(commands) != 1 || !strings.Contains(string(commands[0].Payload), `"reset_local_preferences":true`) {
		t.Fatal("support reset did not explicitly request clearing local preferences")
	}
	rules, err := st.ListCustomerRules(ctx, d.ID)
	if err != nil || len(rules) != 0 {
		t.Fatalf("customer choices remain: %#v %v", rules, err)
	}
	all, err := st.ListRules(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	foundBase := false
	for _, rule := range all {
		foundBase = foundBase || rule.ID == base.ID
	}
	if !foundBase {
		t.Fatal("support reset removed administrator baseline")
	}
	after, err := st.GetDevice(ctx, d.ID)
	if err != nil || after.ID != d.ID || after.Serial != d.Serial || after.RescueSSHPort != 22001 || after.Profile != d.Profile {
		t.Fatalf("support reset changed identity, rescue port or profile: %#v %v", after, err)
	}
}
