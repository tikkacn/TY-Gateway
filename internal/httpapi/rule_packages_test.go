package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestRulePackageSelectionAndDelivery(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TY_RULE_PACKAGES_DIR", dir)
	p := rulePackage{Profile: "managed_loyal", Version: strings.Repeat("a", 64), Categories: []string{"AI"}, Rules: []model.Rule{{ID: "ai", Source: "managed_loyal", SourceType: "provider", Category: "AI", MatchType: "domain_suffix", MatchValue: "openai.com", Action: "PROXY", Enabled: true}, {ID: "default", Source: "managed_loyal", SourceType: "provider", MatchType: "all", Action: "PROXY", Enabled: true, Priority: 9999}}}
	data, _ := json.Marshal(p)
	if e := os.WriteFile(filepath.Join(dir, "managed_loyal.json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	st := store.NewMemoryStore()
	s := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, e := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:06:01", AgentVersion: "0.8.0"})
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	s.customerRulePackage(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"operation":"select","profile":"managed_loyal"}`)), d)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	actual, rs, _, _, e := s.policySnapshot(context.Background(), d.ID)
	if e != nil || actual.RulePackageVersion != p.Version || len(rs) != 2 {
		t.Fatal("selected package not delivered", e)
	}
	w = httptest.NewRecorder()
	s.customerRulePackage(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"operation":"update","profile":"managed_loyal"}`)), d)
	if w.Code != 202 {
		t.Fatal(w.Code)
	}
	if _, e = os.Stat(filepath.Join(dir, "managed_loyal.request")); e != nil {
		t.Fatal("update not queued")
	}
	w = httptest.NewRecorder()
	s.customerRulePackage(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"operation":"select","profile":"managed_black"}`)), d)
	if w.Code != 400 {
		t.Fatal("removed package profile accepted")
	}
	d.AgentVersion = "0.5.0"
	w = httptest.NewRecorder()
	s.customerRulePackage(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"operation":"select","profile":"managed_loyal"}`)), d)
	if w.Code != 409 {
		t.Fatal("old agent accepted")
	}
}

func TestManagedRulePackageAgentVersionGate(t *testing.T) {
	for _, test := range []struct {
		version string
		allowed bool
	}{
		{"", false},
		{"0.5.9", false},
		{"0.6.0", true},
		{"0.6.0-managed-rules", true},
		{"0.7.3", true},
		{"0.8.0", true},
		{"1.0.0", true},
		{"0.6.bad", false},
		{"0.08.0", false},
	} {
		if got := supportsManagedRulePackages(test.version); got != test.allowed {
			t.Errorf("supportsManagedRulePackages(%q) = %t, want %t", test.version, got, test.allowed)
		}
	}
}
