package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"tygateway/internal/model"
)

func localPreferenceFixture(t *testing.T) (*agent, *fakeDaeApplier) {
	t.Helper()
	compiled := []model.CompiledRule{
		{RuleID: "ai", Source: "managed_meta", SourceType: "provider", Category: "AI", Match: "domain_suffix(openai.com)", Action: "PROXY", DefaultAction: "PROXY"},
		{RuleID: "personal", Source: "customer", SourceType: "user", Category: "AI", Match: "domain(private.example)", Action: "DIRECT"},
		{RuleID: "protected", Source: "system", SourceType: "system", Category: "AI", Match: "management(control)", Action: "DIRECT"},
	}
	nodes := []model.Node{{ID: "node-1", Name: "日本节点"}}
	config := model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1", ConfigVersion: 3}, Profile: "managed_meta", ConfigVersion: 3, ServerTime: time.Now().UTC(), DaeSubscriptionManaged: true, Nodes: nodes, Preferences: map[string]string{}, Rules: compiled, BaseRules: compiled}
	customer, _ := json.Marshal(map[string]any{"device": config.Device, "categories": []string{"AI"}, "preferences": map[string]string{}, "rules": []model.Rule{}, "nodes": customerNodes(nodes)})
	helper := &fakeDaeApplier{result: daeApplyResult{Status: "ok", PolicyStatus: "applied", NodeCount: 1, Nodes: customerNodes(nodes), RollbackToken: "recover"}}
	a := &agent{server: "https://unreachable.example.invalid", stateDir: t.TempDir(), state: credentialState{DeviceID: "device-1"}, logger: log.New(io.Discard, "", 0), daeApplier: helper, interfaceName: "eth0", allowDaeProxy: true, localProxyOn: true}
	if err := a.saveAppliedSnapshot(config, customer, "sub-1"); err != nil {
		t.Fatal(err)
	}
	return a, helper
}

func TestLocalNodePreferenceIsAtomicAndNeedsNoCloud(t *testing.T) {
	a, helper := localPreferenceFixture(t)
	response := a.localCustomerRequest(context.Background(), localControlRequest{Method: "POST", Path: "/node-preference", Body: json.RawMessage(`{"category":"AI","node_id":"node-1","expected_revision":0}`)})
	if response.Error != "" || !bytes.Contains(response.Data, []byte(`"storage":"local"`)) || !bytes.Contains(response.Data, []byte(`"applied":true`)) {
		t.Fatalf("offline save failed: %s %s", response.Error, response.Data)
	}
	if helper.policy.Rules[0].Action != "NODE:node-1" || helper.policy.Rules[1].Action != "DIRECT" || helper.policy.Rules[2].Action != "DIRECT" {
		t.Fatal("selection did not reach DAE or overwrote protected rules")
	}
	rebooted := &agent{stateDir: a.stateDir, state: a.state}
	snapshot, err := rebooted.loadAppliedSnapshot()
	if err != nil || snapshot.LocalRevision != 1 || snapshot.LocalPreferences["AI"] != "node-1" || snapshot.Config.Preferences["AI"] != "node-1" {
		t.Fatalf("local snapshot did not survive restart: %v", err)
	}
	before, _ := os.ReadFile(a.snapshotPath())
	helper.result.PolicyStatus = "error"
	response = a.saveLocalNodePreference(context.Background(), []byte(`{"category":"AI","node_id":"@direct","expected_revision":1}`))
	after, _ := os.ReadFile(a.snapshotPath())
	if response.Error == "" || !bytes.Equal(before, after) {
		t.Fatal("failed DAE application changed saved preferences")
	}
}

func TestLocalNodePreferenceDefaultAndValidation(t *testing.T) {
	a, helper := localPreferenceFixture(t)
	for _, body := range []string{`{"category":"management","node_id":"@direct"}`, `{"category":"AI","node_id":"unvalidated"}`, `{"category":"AI","node_id":"node-1","expected_revision":42}`} {
		if result := a.saveLocalNodePreference(context.Background(), []byte(body)); result.Error == "" {
			t.Fatalf("unsafe/stale preference accepted: %s", body)
		}
	}
	if helper.calls != 0 {
		t.Fatal("invalid choices reached helper")
	}
	for _, value := range []string{"@direct", ""} {
		body, _ := json.Marshal(map[string]string{"category": "AI", "node_id": value})
		if result := a.saveLocalNodePreference(context.Background(), body); result.Error != "" {
			t.Fatal(result.Error)
		}
	}
	if helper.policy.Rules[0].Action != "PROXY" {
		t.Fatal("follow default did not restore provider policy")
	}
	if helper.policy.Rules[1].Action != "DIRECT" {
		t.Fatal("category default changed personal rule")
	}
}

func TestLocalNodePreferenceSurvivesCloudSyncAndExplicitReset(t *testing.T) {
	a, helper := localPreferenceFixture(t)
	if result := a.saveLocalNodePreference(context.Background(), []byte(`{"category":"AI","node_id":"node-1"}`)); result.Error != "" {
		t.Fatal(result.Error)
	}
	snapshot, _ := a.loadAppliedSnapshot()
	cloudConfig := snapshot.Config
	cloudConfig.ConfigVersion, cloudConfig.Device.ConfigVersion = 4, 4
	cloudConfig.DaeSubscription = &model.DaeSubscription{ID: "sub-1", URL: "https://provider.example.invalid"}
	cloudConfig.Preferences = map[string]string{"AI": "@direct"}
	cloudConfig.BaseRules[0].Action, cloudConfig.Rules[0].Action = "DIRECT", "DIRECT"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && len(r.URL.Path) > 7 && r.URL.Path[len(r.URL.Path)-7:] == "/config":
			json.NewEncoder(w).Encode(cloudConfig)
		case r.Method == "GET":
			json.NewEncoder(w).Encode(map[string]any{"device": cloudConfig.Device, "categories": []string{"AI"}, "preferences": cloudConfig.Preferences, "nodes": customerNodes(cloudConfig.Nodes), "rules": []model.Rule{}})
		default:
			w.WriteHeader(200)
		}
	}))
	defer server.Close()
	a.server, a.client = server.URL, server.Client()
	a.daeStatus, a.daeSubID, a.daeNodeCount = "ok", "sub-1", 1
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := a.loadAppliedSnapshot()
	if after.LocalPreferences["AI"] != "node-1" || after.Config.BaseRules[0].Action != "NODE:node-1" || helper.policy.Rules[0].Action != "NODE:node-1" {
		t.Fatal("ordinary cloud update overwrote local choice")
	}
	cloudConfig.Preferences = map[string]string{}
	cloudConfig.BaseRules[0].Action, cloudConfig.Rules[0].Action = "PROXY", "PROXY"
	a.configMu.Lock()
	err := a.fetchConfigLockedWithReset(context.Background(), false, false, true, "reset-1")
	a.configMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after, _ = a.loadAppliedSnapshot()
	if len(after.LocalPreferences) != 0 || after.Config.BaseRules[0].Action != "PROXY" || after.LocalRevision != 2 {
		t.Fatal("support reset did not atomically restore baseline")
	}
	if result := a.saveLocalNodePreference(context.Background(), []byte(`{"category":"AI","node_id":"node-1"}`)); result.Error != "" {
		t.Fatal(result.Error)
	}
	a.configMu.Lock()
	err = a.fetchConfigLockedWithReset(context.Background(), false, false, true, "reset-1")
	a.configMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	after, _ = a.loadAppliedSnapshot()
	if after.LocalPreferences["AI"] != "node-1" || after.LocalRevision != 3 {
		t.Fatal("retried reset erased a newer customer choice")
	}
}
