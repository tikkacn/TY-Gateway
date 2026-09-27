package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestCustomerNeverSeesOrSelectsSystemRoutingCategories(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TY_RULE_PACKAGES_DIR", dir)
	p := rulePackage{
		Profile: "managed_loyal", Version: strings.Repeat("a", 64),
		Categories: []string{"AI", "system-lan", "rescue", "China"},
		Rules:      []model.Rule{{ID: "ai", Source: "managed_loyal", SourceType: "provider", Category: "AI", MatchType: "domain_suffix", MatchValue: "example.com", Action: "PROXY", Enabled: true}},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "managed_loyal.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := store.NewMemoryStore()
	s := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:06:02"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = st.UpdateDevice(ctx, d.ID, "", "", p.Profile)
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.customerState(httptest.NewRequest(http.MethodGet, "/", nil), d)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(view.Categories, []string{"AI", "China"}) {
		t.Fatalf("system categories reached customer view: %v", view.Categories)
	}
	for _, category := range []string{"system-lan", "rescue"} {
		body := `{"category":"` + category + `","node_id":"@proxy"}`
		w := httptest.NewRecorder()
		s.setCustomerNodePreference(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), d)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("customer could select %s: %d %s", category, w.Code, w.Body.String())
		}
	}
}
