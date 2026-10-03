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
	"tygateway/internal/ruleseed"
	"tygateway/internal/store"
)

func TestDeviceConfigSeedNegotiationRetainsFullPolicy(t *testing.T) {
	p, _ := ruleseed.Get("managed_meta")
	packageRules := make([]model.Rule, 0, len(p.Rules))
	for _, rule := range p.Rules {
		index := strings.Index(rule.Match, "(")
		packageRules = append(packageRules, model.Rule{ID: rule.RuleID, Source: rule.Source, SourceType: rule.SourceType, Category: rule.Category, MatchType: rule.Match[:index], MatchValue: strings.TrimSuffix(rule.Match[index+1:], ")"), Action: rule.Action, Priority: rule.Priority, Enabled: true})
	}
	dir := t.TempDir()
	t.Setenv("TY_RULE_PACKAGES_DIR", dir)
	raw, _ := json.Marshal(rulePackage{Profile: p.Profile, Name: p.Name, Version: p.Version, PublishedAt: p.PublishedAt, Categories: p.Categories, Rules: packageRules})
	if err := os.WriteFile(filepath.Join(dir, p.Profile+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	st := store.NewMemoryStore()
	s := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:01:00:01", AgentVersion: "0.8.14"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateDevice(context.Background(), d.ID, "", "", p.Profile); err != nil {
		t.Fatal(err)
	}
	get := func(advertisement string) model.DeviceConfig {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/config", nil)
		if advertisement != "" {
			r.Header.Set("X-TY-Rule-Seeds", advertisement)
		}
		w := httptest.NewRecorder()
		s.config(w, r, d.ID)
		var config model.DeviceConfig
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &config) != nil {
			t.Fatalf("config failed: %d", w.Code)
		}
		return config
	}
	full := get("")
	advertised, _ := json.Marshal(ruleseed.Versions())
	compact := get(string(advertised))
	if compact.RuleSeedVersion != p.Version {
		t.Fatal("matching seed not negotiated")
	}
	decoded, err := ruleseed.Hydrate(compact)
	if err != nil {
		t.Fatal(err)
	}
	// The only independently generated field is the response timestamp.
	decoded.ServerTime = full.ServerTime
	if !reflect.DeepEqual(decoded, full) {
		t.Fatal("actual config endpoint changed rule ordering/defaults/actions")
	}
	for _, header := range []string{"bad-json", `{"managed_meta":"wrong-version"}`, strings.Repeat("x", 1025)} {
		fallback := get(header)
		fallback.ServerTime = full.ServerTime
		if !reflect.DeepEqual(fallback, full) {
			t.Fatal("malformed/different seed request did not receive full rules")
		}
	}
}
