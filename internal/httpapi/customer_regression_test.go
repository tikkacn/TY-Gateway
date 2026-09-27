package httpapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"tygateway/internal/customer"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestCustomerRevocationOwnershipAndValidation(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	s := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:AB:CD:EF"})
	if err != nil {
		t.Fatal(err)
	}
	d, _, err = st.RotateCustomerAccess(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	token := customer.NewSession(d.ID, d.CustomerSessionVersion, time.Now(), s.CustomerSessionKey)
	call := func(path, body string) int {
		r := httptest.NewRequest("POST", "/api/v1/customer/"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Code
	}
	adminRule, err := st.CreateRule(ctx, model.Rule{DeviceID: d.ID, Source: "admin", SourceType: "user", MatchType: "domain", MatchValue: "admin.example", Action: "DIRECT", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if code := call("rules/delete", `{"id":"`+adminRule.ID+`"}`); code != 404 {
		t.Fatalf("admin rule deletion: %d", code)
	}
	for _, domain := range []string{"https://a.com", "a.com/path", "a.com,b.com", "a..com", "-a.com", "a com"} {
		if code := call("rules", `{"match_type":"domain","match_value":"`+domain+`","action":"DIRECT"}`); code != 400 {
			t.Fatalf("accepted invalid domain: %d", code)
		}
	}
	before, _ := st.GetDevice(ctx, d.ID)
	body := `{"match_type":"domain_suffix","match_value":" Example.COM. ","action":"BLOCK"}`
	if code := call("rules", body); code != 201 {
		t.Fatalf("create: %d", code)
	}
	after, _ := st.GetDevice(ctx, d.ID)
	if after.ConfigVersion != before.ConfigVersion+1 {
		t.Fatal("rule did not bump version")
	}
	if code := call("rules", body); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	if code := call("rules", `{"match_type":"cidr","match_value":"192.0.2.99/24, 2001:db8::1/64","action":"DIRECT"}`); code != 201 {
		t.Fatalf("valid IPv4/IPv6 IP rule rejected: %d", code)
	}
	if code := call("rules", `{"match_type":"cidr","match_value":"192.0.2.1/99","action":"DIRECT"}`); code != 400 {
		t.Fatalf("invalid CIDR accepted: %d", code)
	}
	if code := call("rules", `{"match_type":"ip","match_value":"https://example.com","action":"DIRECT"}`); code != 400 {
		t.Fatalf("non-IP match accepted as an IP rule: %d", code)
	}
	if code := call("logout", `{}`); code != 200 {
		t.Fatal(code)
	}
	if code := call("override", `{"action":"PROXY","duration_minutes":30}`); code != 403 {
		t.Fatalf("logout did not revoke: %d", code)
	}
	d, _, _ = st.RotateCustomerAccess(ctx, d.ID)
	token = customer.NewSession(d.ID, d.CustomerSessionVersion, time.Now(), s.CustomerSessionKey)
	st.RotateCustomerAccess(ctx, d.ID)
	if code := call("action", `{"action":"report_status"}`); code != 403 {
		t.Fatalf("rotation did not revoke: %d", code)
	}
	d, _, _ = st.RotateCustomerAccess(ctx, d.ID)
	token = customer.NewSession(d.ID, d.CustomerSessionVersion, time.Now(), s.CustomerSessionKey)
	if _, err = st.UpdateIdentity(ctx, d.ID, "new owner", "owner@example.com", ""); err != nil {
		t.Fatal(err)
	}
	if code := call("action", `{"action":"report_status"}`); code != 403 {
		t.Fatalf("owner change did not revoke: %d", code)
	}
	a, _ := st.GetCustomerAuthBySerial(ctx, d.Serial)
	if a.CustomerAccessHash != "" {
		t.Fatal("old credential retained for new owner")
	}
}

func TestCustomerWriteAdmission(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	s := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, _ := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:01:02"})
	token := customer.NewSession(d.ID, d.CustomerSessionVersion, time.Now(), s.CustomerSessionKey)
	for i := 0; i < 31; i++ {
		r := httptest.NewRequest("POST", "/api/v1/customer/action", strings.NewReader(`{"action":"report_status"}`))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		expected := 202
		if i == 30 {
			expected = 429
		}
		if w.Code != expected {
			t.Fatalf("request %d: got %d", i, w.Code)
		}
	}
}
