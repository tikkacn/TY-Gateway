package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/ruleseed"
)

func TestInitialCatalogDoesNotClaimAppliedNodesOrPolicy(t *testing.T) {
	a := &agent{stateDir: t.TempDir(), state: credentialState{DeviceID: "device-1"}}
	response := a.localCustomerRequest(context.Background(), localControlRequest{Method: "GET", Path: "/me"})
	var state struct {
		Pending  bool                 `json:"initialization_pending"`
		Nodes    []model.CustomerNode `json:"nodes"`
		Packages []map[string]any     `json:"rule_packages"`
	}
	if response.Error != "" || json.Unmarshal(response.Data, &state) != nil || !state.Pending || len(state.Nodes) != 0 || len(state.Packages) != 4 {
		t.Fatal("early menu claims applied state or is unavailable")
	}
	if a.onboardingStatus().Prepared {
		t.Fatal("seed-only device incorrectly marked ready")
	}
	if _, err := os.Stat(a.snapshotPath()); !os.IsNotExist(err) {
		t.Fatal("early menu created an applied snapshot")
	}
	if err := a.saveRuleCatalog("managed_meta", []byte(`{"rule_packages":[{"id":"managed_meta","name":"live"}],"nodes":[{"id":"unvalidated"}]}`)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(a.initialCustomerCatalog()), "unvalidated") {
		t.Fatal("unvalidated cloud node was exposed")
	}
}

func TestSeedConfigPreparedAtInstallationWithProxyOff(t *testing.T) {
	p, _ := ruleseed.Get("managed_meta")
	base := append([]model.CompiledRule(nil), p.Rules...)
	full := model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1", ConfigVersion: 7}, Profile: p.Profile, RulePackageVersion: p.Version, ConfigVersion: 7, ServerTime: time.Now().UTC(), BaseRules: base, Rules: base, DaeSubscriptionManaged: true, DaeSubscription: &model.DaeSubscription{ID: "subscription-1", URL: "https://example.invalid/?token=private"}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			var versions map[string]string
			if json.Unmarshal([]byte(r.Header.Get("X-TY-Rule-Seeds")), &versions) != nil {
				t.Error("missing seed advertisement")
			}
			_ = json.NewEncoder(w).Encode(ruleseed.Compact(full, versions))
		case strings.HasSuffix(r.URL.Path, "/customer/me"):
			_ = json.NewEncoder(w).Encode(map[string]any{"device": full.Device, "rule_packages": ruleseed.Catalog(), "preferences": map[string]string{}})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	helper := &fakeDaeApplier{result: daeApplyResult{Status: "ok", NodeCount: 1, Nodes: fakeValidatedNodes(1), PolicyStatus: "prepared"}}
	a := &agent{server: server.URL, client: server.Client(), stateDir: t.TempDir(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, allowDaeProxy: true, daeApplier: helper, logger: log.New(io.Discard, "", 0)}
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := a.onboardingStatus()
	if !state.Prepared || state.ProxyEnabled || helper.policy.ProxyEnabled || helper.policy.RulePackageVersion != p.Version {
		t.Fatalf("preparation changed proxy switch or did not complete: %#v", state)
	}
	snapshot, err := a.loadAppliedSnapshot()
	if err != nil || snapshot.Config.RuleSeedVersion != "" || len(snapshot.Config.BaseRules) != len(base) {
		t.Fatal("snapshot is not self-contained", err)
	}
	for i, r := range snapshot.Config.BaseRules {
		if r.Match != base[i].Match {
			t.Fatal("seed expression was lost")
		}
	}
	raw, _ := os.ReadFile(a.snapshotPath())
	if strings.Contains(string(raw), "token=private") {
		t.Fatal("subscription secret entered snapshot")
	}
	if _, err := os.Stat(filepath.Join(a.stateDir, localProxyFile)); !os.IsNotExist(err) {
		t.Fatal("preparation persisted a proxy switch change")
	}
}

func TestSeedMismatchFetchesCompleteRulesBeforeApply(t *testing.T) {
	requests := 0
	full := model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1", ConfigVersion: 1}, Profile: "gfw_precise", ServerTime: time.Now().UTC(), ConfigVersion: 1, DaeSubscriptionManaged: true, BaseRules: []model.CompiledRule{{Match: "all()", Action: "DIRECT"}}, Rules: []model.CompiledRule{{Match: "all()", Action: "DIRECT"}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config") {
			requests++
			config := full
			if requests == 1 {
				if r.Header.Get("X-TY-Rule-Seeds") == "" {
					t.Error("first request did not advertise seeds")
				}
				config.RuleSeedVersion = strings.Repeat("a", 64)
			} else if r.Header.Get("X-TY-Rule-Seeds") != "" {
				t.Error("full fallback still advertised seeds")
			}
			_ = json.NewEncoder(w).Encode(config)
		} else if strings.HasSuffix(r.URL.Path, "/customer/me") {
			_ = json.NewEncoder(w).Encode(map[string]any{"device": full.Device, "preferences": map[string]string{}})
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	helper := &fakeDaeApplier{result: daeApplyResult{Status: "unbound", PolicyStatus: "prepared"}}
	a := &agent{server: server.URL, client: server.Client(), stateDir: t.TempDir(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, daeApplier: helper, logger: log.New(io.Discard, "", 0)}
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 || helper.calls != 1 || helper.policy.Rules[0].Match != "all()" {
		t.Fatal("mismatched/partial seed was applied or fallback was not bounded")
	}
	if a.onboardingStatus().Prepared {
		t.Fatal("no-subscription fallback incorrectly marked prepared")
	}
}
