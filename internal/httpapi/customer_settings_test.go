package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestDeviceSettingsReplaceRejectsStaleAndInvalidRules(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, secret, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:98"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := st.SaveCustomerRule(ctx, model.Rule{DeviceID: d.ID, MatchType: "domain", MatchValue: "old.example", Action: "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = st.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/device/" + d.ID + "/customer/settings"
	send := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, signedRequest(http.MethodPost, path, []byte(body), d.ID, auth.SecretHash(secret)))
		return w
	}
	base := `{"expected_version":` + strconv.FormatInt(d.ConfigVersion, 10) + `,"rules":[{"match_type":"domain_suffix","match_value":"new.example","action":"PROXY"}],"preferences":{}}`
	bad := send(strings.Replace(base, "new.example", "bad domain", 1))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("bad rule status=%d %s", bad.Code, bad.Body.String())
	}
	stale := send(strings.Replace(base, strconv.FormatInt(d.ConfigVersion, 10), strconv.FormatInt(d.ConfigVersion-1, 10), 1))
	if stale.Code != http.StatusConflict {
		t.Fatalf("stale status=%d %s", stale.Code, stale.Body.String())
	}
	rules, err := st.ListCustomerRules(ctx, d.ID)
	if err != nil || len(rules) != 1 || rules[0].ID != old.ID {
		t.Fatalf("failed call mutated rules: %#v %v", rules, err)
	}
	ok := send(base)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), `"ok":true`) {
		t.Fatalf("replacement status=%d %s", ok.Code, ok.Body.String())
	}
	rules, err = st.ListCustomerRules(ctx, d.ID)
	if err != nil || len(rules) != 1 || rules[0].MatchValue != "new.example" {
		t.Fatalf("replacement rules=%#v %v", rules, err)
	}
	customer := httptest.NewRecorder()
	srv.ServeHTTP(customer, httptest.NewRequest(http.MethodPost, "/api/v1/customer/settings", strings.NewReader(base)))
	if customer.Code != http.StatusUnauthorized {
		t.Fatalf("cloud customer route exposed batch replacement: %d", customer.Code)
	}
}
