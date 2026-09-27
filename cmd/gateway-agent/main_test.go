package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/model"
)

type fakeDaeApplier struct {
	manageSubscription bool
	directive          *model.DaeSubscription
	policy             *model.DaePolicy
	calls              int
	result             daeApplyResult
	results            []daeApplyResult
	err                error
	rollbackCalls      int
	stopCalls          int
	stopped            bool
	stopErr            error
}

func fakeValidatedNodes(count int) []model.CustomerNode {
	nodes := make([]model.CustomerNode, 0, count)
	for i := 0; i < count; i++ {
		nodes = append(nodes, model.CustomerNode{ID: fmt.Sprintf("%016x", i+1), Name: fmt.Sprintf("node-%d", i+1)})
	}
	return nodes
}

func TestCompiledSelectionsUseOnlyDaeValidatedNodes(t *testing.T) {
	rules := []model.CompiledRule{{Action: "NODE:valid"}, {Action: "NODE:old"}, {Action: "DIRECT"}}
	nodes := []model.CustomerNode{{ID: "valid", Name: "valid node"}}
	known := safeCompiledNodeActions(rules, nodes, false)
	if known[0].Action != "NODE:valid" || known[1].Action != "AUTO" || known[2].Action != "DIRECT" {
		t.Fatalf("known node selection was not sanitized safely: %#v", known)
	}
	unknown := safeCompiledNodeActions(rules, nodes, true)
	if unknown[0].Action != "AUTO" || rules[0].Action != "NODE:valid" {
		t.Fatalf("subscription refresh did not stage safe automatic routing: %#v", unknown)
	}
}

func (f *fakeDaeApplier) Apply(_ context.Context, manageSubscription bool, directive *model.DaeSubscription, policy *model.DaePolicy) (daeApplyResult, error) {
	f.manageSubscription, f.directive, f.policy = manageSubscription, directive, policy
	f.calls++
	result := f.result
	if f.calls <= len(f.results) {
		result = f.results[f.calls-1]
	}
	if f.err == nil && policy != nil && policy.ProxyEnabled && result.Status == "ok" && result.PolicyStatus == "applied" {
		f.stopped = false
	}
	return result, f.err
}

func (f *fakeDaeApplier) Rollback(_ context.Context, token string) error {
	if token == "" {
		return fmt.Errorf("missing rollback token")
	}
	f.rollbackCalls++
	return nil
}

func (f *fakeDaeApplier) Stop(context.Context) error {
	f.stopCalls++
	if f.stopErr != nil {
		return f.stopErr
	}
	f.stopped = true
	return nil
}

func (f *fakeDaeApplier) ServiceActive(context.Context) (bool, error) {
	return !f.stopped, nil
}

func TestDaePolicyConfirmationRequiresAppliedNativeNodesWhenEnabling(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result daeApplyResult
		want   bool
	}{
		{name: "fully applied", result: daeApplyResult{Status: "ok", PolicyStatus: "applied", NodeCount: 16}, want: true},
		{name: "only prepared", result: daeApplyResult{Status: "ok", PolicyStatus: "prepared", NodeCount: 16}},
		{name: "no native nodes", result: daeApplyResult{Status: "ok", PolicyStatus: "applied"}},
		{name: "reload failed", result: daeApplyResult{Status: "error", PolicyStatus: "error", NodeCount: 16}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := daePolicyConfirmed(true, tc.result, nil); got != tc.want {
				t.Fatalf("daePolicyConfirmed(true, %#v) = %t; want %t", tc.result, got, tc.want)
			}
		})
	}
	if !daePolicyConfirmed(false, daeApplyResult{Status: "unchanged", PolicyStatus: "prepared"}, nil) {
		t.Fatal("a validated direct-only policy should be accepted as prepared")
	}
}

func TestSetLocalProxyStaysOffUnlessDaeConfirmsAppliedPolicy(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.DeviceConfig{
				Device:     model.CustomerDevice{ID: "device-1", Serial: "AABBCCDDEEFF"},
				ServerTime: time.Now().UTC(), Profile: "gfw_precise", DaeSubscriptionManaged: true,
				DaeSubscription: &model.DaeSubscription{ID: "sub-1", URL: "https://provider.example.invalid/sub"},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/customer/me"):
			_ = json.NewEncoder(w).Encode(map[string]any{"device": model.CustomerDevice{ID: "device-1"}, "rules": []model.Rule{}, "nodes": []model.CustomerNode{}, "preferences": map[string]string{}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/heartbeat"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/nodes"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	applier := &fakeDaeApplier{results: []daeApplyResult{
		{Status: "ok", NodeCount: 16, Nodes: fakeValidatedNodes(16), PolicyStatus: "prepared"},
		{Status: "ok", NodeCount: 16, Nodes: fakeValidatedNodes(16), PolicyStatus: "prepared"},
		{Status: "unchanged", PolicyStatus: "prepared"},
	}}
	a := &agent{
		server: server.URL, stateDir: t.TempDir(), allowDaeProxy: true,
		client: server.Client(), state: credentialState{DeviceID: "device-1", DeviceSecret: "test-secret"},
		daeApplier: applier, logger: log.New(io.Discard, "", 0),
	}

	state := a.setLocalProxy(context.Background(), true)
	if state.Enabled || state.Applied || state.Error == "" {
		t.Fatalf("unconfirmed Dae policy must fail closed; got %#v", state)
	}
	if applier.policy == nil || applier.policy.ProxyEnabled {
		t.Fatalf("failed enable did not finish by requesting direct mode: %#v", applier.policy)
	}
	data, err := os.ReadFile(a.localProxyPath())
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &saved); err != nil || saved.Enabled {
		t.Fatalf("failed enable persisted an enabled switch: saved=%#v err=%v", saved, err)
	}
}

func TestSetLocalProxyReportsEnabledOnlyAfterDaeAppliesPolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.DeviceConfig{
				Device:     model.CustomerDevice{ID: "device-1", Serial: "AABBCCDDEEFF"},
				ServerTime: time.Now().UTC(), Profile: "gfw_precise", DaeSubscriptionManaged: true,
				DaeSubscription: &model.DaeSubscription{ID: "sub-1", URL: "https://provider.example.invalid/sub"},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/customer/me"):
			_ = json.NewEncoder(w).Encode(map[string]any{"device": model.CustomerDevice{ID: "device-1"}, "rules": []model.Rule{}, "nodes": []model.CustomerNode{}, "preferences": map[string]string{}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/heartbeat"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/nodes"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	applier := &fakeDaeApplier{result: daeApplyResult{Status: "ok", NodeCount: 16, Nodes: fakeValidatedNodes(16), PolicyStatus: "applied"}}
	a := &agent{
		server: server.URL, stateDir: t.TempDir(), allowDaeProxy: true,
		client: server.Client(), state: credentialState{DeviceID: "device-1", DeviceSecret: "test-secret"},
		daeApplier: applier, logger: log.New(io.Discard, "", 0),
	}

	state := a.setLocalProxy(context.Background(), true)
	if !state.Enabled || !state.Applied || !state.Ready || !state.Subscription || state.NodeCount != 16 {
		t.Fatalf("success requires Dae to apply policy and confirm parsed nodes; got %#v", state)
	}
	data, err := os.ReadFile(a.localProxyPath())
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &saved); err != nil || !saved.Enabled {
		t.Fatalf("confirmed enable was not persisted: saved=%#v err=%v", saved, err)
	}
}

func TestLocalSwitchOffStopsDaeAndStaysOffAfterRestart(t *testing.T) {
	dir := t.TempDir()
	applier := &fakeDaeApplier{result: daeApplyResult{Status: "unchanged", PolicyStatus: "prepared"}}
	a := &agent{stateDir: dir, state: credentialState{DeviceID: "device-1"}, daeApplier: applier, localProxyOn: true}
	snapshot, err := json.Marshal(appliedSnapshot{Config: model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1"}, Profile: "gfw_precise"}, Customer: json.RawMessage(`{}`)})
	if err != nil || writePrivateFile(a.snapshotPath(), snapshot) != nil {
		t.Fatal("could not prepare the cached policy")
	}
	state := a.setLocalProxy(context.Background(), false)
	if state.Enabled || state.Applied || state.DaemonActive || applier.stopCalls != 1 || state.Error != "" {
		t.Fatalf("off did not stop dae: state=%#v stopCalls=%d", state, applier.stopCalls)
	}
	// Even if an external action started dae before the next boot, the saved
	// off state must stop it again without contacting Cloud.
	applier.stopped = false
	restarted := &agent{stateDir: dir, state: credentialState{DeviceID: "device-1"}, daeApplier: applier}
	if err := restarted.loadLocalProxy(); err != nil || restarted.localProxyOn {
		t.Fatalf("off was not persisted: err=%v", err)
	}
	if err := restarted.restoreLocalSwitch(context.Background()); err != nil || !applier.stopped || applier.stopCalls != 2 {
		t.Fatalf("off was not restored: err=%v stopCalls=%d", err, applier.stopCalls)
	}
}

func TestLocalSwitchOnRestoresCachedPolicyAfterRestart(t *testing.T) {
	dir := t.TempDir()
	nodes := fakeValidatedNodes(1)
	applier := &fakeDaeApplier{stopped: true, result: daeApplyResult{Status: "ok", PolicyStatus: "applied", NodeCount: 1, Nodes: nodes}}
	a := &agent{stateDir: dir, state: credentialState{DeviceID: "device-1"}, daeApplier: applier, allowDaeProxy: true}
	snapshot, err := json.Marshal(appliedSnapshot{SubscriptionID: "sub-1", Config: model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1"}, Profile: "gfw_precise", DaeSubscriptionManaged: true, Nodes: []model.Node{{ID: nodes[0].ID, Name: nodes[0].Name}}}, Customer: json.RawMessage(`{}`)})
	if err != nil || writePrivateFile(a.snapshotPath(), snapshot) != nil || a.saveLocalProxy(true) != nil {
		t.Fatal("could not prepare the saved on state")
	}
	if err := a.loadLocalProxy(); err != nil || !a.localProxyOn {
		t.Fatalf("on was not persisted: err=%v", err)
	}
	if err := a.restoreLocalSwitch(context.Background()); err != nil {
		t.Fatalf("offline on restore failed: %v", err)
	}
	state := a.localControlStatus()
	if !state.Enabled || !state.Applied || !state.DaemonActive || state.NodeCount != 1 {
		t.Fatalf("on was not actually restored: %#v", state)
	}
}

func TestLocalSwitchRetriesBootRestoreWhenDaeIsAlreadyActive(t *testing.T) {
	dir := t.TempDir()
	nodes := fakeValidatedNodes(1)
	applier := &fakeDaeApplier{results: []daeApplyResult{
		{Status: "error", ErrorCode: "dae_reload_failed"},
		{Status: "ok", PolicyStatus: "applied", NodeCount: 1, Nodes: nodes},
	}}
	a := &agent{
		stateDir: dir, state: credentialState{DeviceID: "device-1"},
		daeApplier: applier, allowDaeProxy: true, logger: log.New(io.Discard, "", 0),
	}
	snapshot, err := json.Marshal(appliedSnapshot{
		SubscriptionID: "sub-1",
		Config: model.DeviceConfig{
			Device: model.CustomerDevice{ID: "device-1"}, Profile: "gfw_precise", DaeSubscriptionManaged: true,
			Nodes: []model.Node{{ID: nodes[0].ID, Name: nodes[0].Name}},
		}, Customer: json.RawMessage(`{}`),
	})
	if err != nil || writePrivateFile(a.snapshotPath(), snapshot) != nil || a.saveLocalProxy(true) != nil {
		t.Fatal("could not prepare the saved on state")
	}
	if err := a.loadLocalProxy(); err != nil || !a.localProxyOn {
		t.Fatalf("on was not persisted: %v", err)
	}
	if err := a.restoreLocalSwitch(context.Background()); err == nil {
		t.Fatal("initial boot-time restore should fail")
	}
	if state := a.localControlStatus(); state.Ready || !state.DaemonActive {
		t.Fatalf("test requires an active daemon with unconfirmed policy: %#v", state)
	}
	a.reconcileRunningService()
	if state := a.localControlStatus(); !state.Applied || !state.Ready || !state.DaemonActive || applier.calls != 2 {
		t.Fatalf("running daemon was not reconciled after the boot race: state=%#v calls=%d", state, applier.calls)
	}
}

func TestValidateURLRequiresHTTPS(t *testing.T) {
	if err := validateURL("https://oec.example.test"); err != nil {
		t.Fatalf("expected HTTPS URL to pass: %v", err)
	}
	for _, raw := range []string{"http://oec.example.test", "/relative", "https://"} {
		if err := validateURL(raw); err == nil {
			t.Fatalf("expected URL to fail validation: %q", raw)
		}
	}
}

func TestWritePrivateFileCreatesReadableState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "credentials.json")
	if err := writePrivateFile(path, []byte(`{"device_id":"id"}`)); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"device_id":"id"}` {
		t.Fatalf("unexpected file contents: %s", b)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("credentials file is not private: %v", err)
		}
	}
}

func TestSignedRequestIsVerifiedByCloudBoundary(t *testing.T) {
	const rawSecret = "test-device-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := auth.VerifyRequest(r, body, auth.SecretHash(rawSecret), time.Now().UTC(), auth.NewNonceCache(10), 5*time.Minute); err != nil {
			t.Fatalf("signature was not accepted: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	a := &agent{
		server: server.URL,
		state:  credentialState{DeviceID: "device-1", DeviceSecret: rawSecret},
		client: server.Client(),
	}
	_, status, err := a.signedRequest(context.Background(), http.MethodPost, "/test", []byte(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", status)
	}
}

func TestConfigIsAppliedByDaeHelperAndURLIsNotPersistedOrReported(t *testing.T) {
	const (
		secret = "agent-secret"
		subID  = "sub-123"
		rawURL = "https://provider.example.invalid/subscribe?token=must-not-persist"
	)
	var receivedReport model.DeviceReport
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.DeviceConfig{
				Device:  model.CustomerDevice{ID: "device-1", Serial: "AABBCCDDEEFF"},
				Profile: "gfw_precise", ServerTime: time.Now().UTC(), DaeSubscriptionManaged: true,
				DaeSubscription: &model.DaeSubscription{ID: subID, URL: rawURL},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/customer/me"):
			_ = json.NewEncoder(w).Encode(map[string]any{"device": model.CustomerDevice{ID: "device-1"}, "rules": []model.Rule{}, "nodes": []model.CustomerNode{}, "preferences": map[string]string{}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/heartbeat"):
			if err := json.NewDecoder(r.Body).Decode(&receivedReport); err != nil {
				t.Errorf("decode heartbeat: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/nodes"):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	applier := &fakeDaeApplier{result: daeApplyResult{Status: "ok", NodeCount: 25, Nodes: fakeValidatedNodes(25), PolicyStatus: "prepared"}}
	a := &agent{
		server: server.URL, stateDir: t.TempDir(), client: server.Client(),
		state:      credentialState{DeviceID: "device-1", DeviceSecret: secret},
		daeApplier: applier, logger: log.New(io.Discard, "", 0),
	}
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if applier.directive == nil || applier.directive.ID != subID || applier.directive.URL != rawURL {
		t.Fatalf("unexpected helper directive: %#v", applier.directive)
	}
	if !applier.manageSubscription || applier.policy == nil || applier.policy.ProxyEnabled || !applier.policy.SubscriptionPresent {
		t.Fatalf("expected a prepared, subscription-bound, proxy-disabled policy: %#v", applier)
	}
	stored, err := os.ReadFile(a.snapshotPath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), rawURL) || strings.Contains(string(stored), "must-not-persist") {
		t.Fatal("subscription URL was persisted in the agent config snapshot")
	}
	if err := a.sendStatus(context.Background(), "/heartbeat"); err != nil {
		t.Fatal(err)
	}
	if receivedReport.DaeStatus != "ok" || receivedReport.DaeSubscriptionID != subID || receivedReport.DaeNodeCount != 25 {
		t.Fatalf("dae result was not reported: %#v", receivedReport)
	}
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if applier.calls != 2 {
		t.Fatalf("validated nodes were not rebound into the policy: calls=%d", applier.calls)
	}
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	if applier.calls != 2 {
		t.Fatalf("stable subscription and policy reapplied %d times", applier.calls)
	}
}

func TestFailedDaeUpdatePreservesLocalRulesAndNodes(t *testing.T) {
	version := int64(1)
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config"):
			_ = json.NewEncoder(w).Encode(model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1", ConfigVersion: version}, ConfigVersion: version, Profile: "gfw_precise", ServerTime: time.Now().UTC(), DaeSubscriptionManaged: true, DaeSubscription: &model.DaeSubscription{ID: "sub-1", URL: "https://provider.example.invalid/private"}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/customer/me"):
			_ = json.NewEncoder(w).Encode(map[string]any{"device": model.CustomerDevice{ID: "device-1", ConfigVersion: version}, "rules": []model.Rule{}, "nodes": []model.CustomerNode{}, "preferences": map[string]string{}, "categories": []string{"AI"}})
		case r.Method == http.MethodPost && (strings.HasSuffix(r.URL.Path, "/heartbeat") || strings.HasSuffix(r.URL.Path, "/nodes")):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer cloud.Close()
	a := &agent{server: cloud.URL, stateDir: t.TempDir(), client: cloud.Client(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, daeApplier: &fakeDaeApplier{results: []daeApplyResult{{Status: "ok", PolicyStatus: "prepared", NodeCount: 2, Nodes: fakeValidatedNodes(2)}, {Status: "error", PolicyStatus: "error", ErrorCode: "dae_reload_failed"}}}, logger: log.New(io.Discard, "", 0)}
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(a.snapshotPath())
	if err != nil {
		t.Fatal(err)
	}
	version = 2
	if err := a.fetchConfig(context.Background()); err == nil {
		t.Fatal("failed dae update was reported as successful")
	}
	after, err := os.ReadFile(a.snapshotPath())
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed dae update overwrote last-known-good local snapshot")
	}
	cloud.Close()
	response := a.localCustomerRequest(context.Background(), localControlRequest{Action: "customer", Method: "GET", Path: "/me"})
	if response.Error != "" || !bytes.Contains(response.Data, []byte(`"node-2"`)) || bytes.Contains(response.Data, []byte(`"config_version":2`)) {
		t.Fatalf("offline local picker did not retain previous validated nodes: %s", response.Error)
	}
}

func TestHeartbeatFailureDoesNotBlockConfigurationSync(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		case strings.HasSuffix(r.URL.Path, "/config"):
			_ = json.NewEncoder(w).Encode(model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1", ConfigVersion: 2}, ConfigVersion: 2, Profile: "gfw_precise", ServerTime: time.Now().UTC()})
		case strings.HasSuffix(r.URL.Path, "/customer/me"):
			_ = json.NewEncoder(w).Encode(map[string]any{"device": model.CustomerDevice{ID: "device-1", ConfigVersion: 2}, "rules": []model.Rule{}, "nodes": []model.CustomerNode{}, "preferences": map[string]string{}})
		case strings.HasSuffix(r.URL.Path, "/commands"):
			_ = json.NewEncoder(w).Encode(commandEnvelope{Commands: []model.Command{}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer cloud.Close()
	a := &agent{server: cloud.URL, stateDir: t.TempDir(), client: cloud.Client(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, configEvery: time.Minute, logger: log.New(io.Discard, "", 0)}
	if err := a.cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "heartbeat") {
		t.Fatalf("heartbeat failure was not reported: %v", err)
	}
	snapshot, err := a.loadAppliedSnapshot()
	if err != nil || snapshot.Config.ConfigVersion != 2 {
		t.Fatalf("configuration was blocked by heartbeat failure: version=%d err=%v", snapshot.Config.ConfigVersion, err)
	}
}

func TestNodePreferenceSaveQueuesConfigSyncWithoutWaitingForCloudReadback(t *testing.T) {
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/customer/node-preference") && r.Method == http.MethodPost {
			_ = json.NewEncoder(w).Encode(map[string]any{"config_version": 3, "preferences": map[string]string{"AI": "node-1"}})
			return
		}
		http.Error(w, "config readback unavailable", http.StatusServiceUnavailable)
	}))
	defer cloud.Close()
	a := &agent{server: cloud.URL, client: cloud.Client(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, syncNow: make(chan struct{}, 1), logger: log.New(io.Discard, "", 0)}
	response := a.localCustomerRequest(context.Background(), localControlRequest{Method: http.MethodPost, Path: "/node-preference", Body: json.RawMessage(`{"category":"AI","node_id":"node-1"}`)})
	if response.Error != "" || !bytes.Contains(response.Data, []byte(`"config_version":3`)) || len(a.syncNow) != 1 {
		t.Fatalf("cloud save did not queue an independent device sync: error=%q data=%s queued=%d", response.Error, response.Data, len(a.syncNow))
	}
}

func TestFailedSnapshotPreparationRequestsDaeRollback(t *testing.T) {
	version := int64(1)
	invalidPrefs := false
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/config"):
			_ = json.NewEncoder(w).Encode(model.DeviceConfig{Device: model.CustomerDevice{ID: "device-1", ConfigVersion: version}, ConfigVersion: version, Profile: "gfw_precise", ServerTime: time.Now().UTC(), DaeSubscriptionManaged: true, DaeSubscription: &model.DaeSubscription{ID: "sub-1", URL: "https://provider.example.invalid/private"}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/customer/me"):
			prefs := any(map[string]string{})
			if invalidPrefs {
				prefs = "malformed"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"device": model.CustomerDevice{ID: "device-1", ConfigVersion: version}, "rules": []model.Rule{}, "nodes": []model.CustomerNode{}, "preferences": prefs})
		case r.Method == http.MethodPost && (strings.HasSuffix(r.URL.Path, "/heartbeat") || strings.HasSuffix(r.URL.Path, "/nodes")):
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer cloud.Close()
	applier := &fakeDaeApplier{results: []daeApplyResult{{Status: "ok", PolicyStatus: "prepared", NodeCount: 2, Nodes: fakeValidatedNodes(2), RollbackToken: "first"}, {Status: "ok", PolicyStatus: "prepared", NodeCount: 2, Nodes: fakeValidatedNodes(2), RollbackToken: "second"}}}
	a := &agent{server: cloud.URL, stateDir: t.TempDir(), client: cloud.Client(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, daeApplier: applier, logger: log.New(io.Discard, "", 0)}
	if err := a.fetchConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(a.snapshotPath())
	version, invalidPrefs = 2, true
	if err := a.fetchConfig(context.Background()); err == nil {
		t.Fatal("malformed customer snapshot was accepted")
	}
	after, _ := os.ReadFile(a.snapshotPath())
	if applier.rollbackCalls != 1 || !bytes.Equal(before, after) || a.daeSubID != "sub-1" || a.daeStatus != "ok" {
		t.Fatalf("candidate was not rolled back: rollbacks=%d sub=%q status=%q", applier.rollbackCalls, a.daeSubID, a.daeStatus)
	}
}

func TestMakeDaePolicyFailsClosedAfterProxyExpiry(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)
	policy := makeDaePolicy("https://cloud.example.test/api", "eth0", model.DeviceConfig{
		Device:  model.CustomerDevice{CustomerOverrideAction: "PROXY", CustomerOverrideUntil: &past},
		Profile: "gfw_precise", ServerTime: time.Now().UTC(), DaeSubscriptionManaged: true,
		DaeSubscription: &model.DaeSubscription{ID: "sub-1"},
	}, true)
	if policy.ProxyEnabled || !policy.SubscriptionPresent || len(policy.DirectHosts) != 1 || policy.DirectHosts[0] != "cloud.example.test" {
		t.Fatalf("expired global proxy mode was not disabled or management host missing: %#v", policy)
	}
}

func TestMakeDaePolicyRequiresLocalAllowGateAndBindsSingleOECInterface(t *testing.T) {
	until := time.Now().UTC().Add(time.Hour)
	config := model.DeviceConfig{
		Device:  model.CustomerDevice{CustomerOverrideAction: "PROXY", CustomerOverrideUntil: &until},
		Profile: "blackmatrix7", ServerTime: time.Now().UTC(), DaeSubscriptionManaged: true,
		DaeSubscription: &model.DaeSubscription{ID: "sub-1"},
	}
	locked := makeDaePolicy("https://cloud.example.test/api", "eth0", config, false)
	if locked.ProxyEnabled {
		t.Fatal("cloud proxy request bypassed the local default-off safety gate")
	}
	enabled := makeDaePolicy("https://cloud.example.test/api", "eth0", config, true)
	if !enabled.ProxyEnabled || enabled.Interface != "eth0" {
		t.Fatalf("explicitly allowed proxy policy lost the OEC interface: %#v", enabled)
	}
}

func TestLocalDaeRulesUseProxyCapableBaseWhenEnabled(t *testing.T) {
	config := model.DeviceConfig{
		Rules:     []model.CompiledRule{{RuleID: "active-direct", Action: "DIRECT"}},
		BaseRules: []model.CompiledRule{{RuleID: "gfw-proxy", Action: "PROXY"}},
	}
	got := localDaeRules(config, true)
	if len(got) != 1 || got[0].RuleID != "gfw-proxy" {
		t.Fatalf("local proxy enable did not select proxy-capable base rules: %#v", got)
	}
	got = localDaeRules(config, false)
	if len(got) != 1 || got[0].RuleID != "active-direct" {
		t.Fatalf("local direct mode did not preserve active cloud rules: %#v", got)
	}
}

func TestEnvBoolFailsClosedOnUnknownValue(t *testing.T) {
	t.Setenv("TY_TEST_BOOL", "not-a-boolean")
	if envBool("TY_TEST_BOOL", false) {
		t.Fatal("unrecognized environment value must not enable proxy routing")
	}
	t.Setenv("TY_TEST_BOOL", "true")
	if !envBool("TY_TEST_BOOL", false) {
		t.Fatal("explicit true environment value was ignored")
	}
}

func TestDaeSubscriptionIsNotFetchedOnRoutineConfigPoll(t *testing.T) {
	a := &agent{daeStatus: "ok", daeSubID: "sub-1", daeNodeCount: 25}
	current := &model.DaeSubscription{ID: "sub-1", URL: "https://provider.example.invalid/sub?token=secret"}
	if a.shouldApplyDaeSubscription(current, false) {
		t.Fatal("routine config polling would repeatedly fetch and reload an unchanged subscription")
	}
	if !a.shouldApplyDaeSubscription(current, true) {
		t.Fatal("explicit subscription refresh did not force dae re-parse")
	}
	if !a.shouldApplyDaeSubscription(&model.DaeSubscription{ID: "sub-2"}, false) {
		t.Fatal("subscription rebind did not trigger dae apply")
	}
	a.daeStatus = "error"
	if !a.shouldApplyDaeSubscription(current, false) {
		t.Fatal("failed dae subscription was not retried")
	}
	a.daeStatus, a.daeSubID = "unbound", ""
	if a.shouldApplyDaeSubscription(nil, false) {
		t.Fatal("unchanged unbound state triggered an unnecessary dae reload")
	}
}

func TestScheduledSubscriptionChecksRespectIntervalsAndRequireActiveProxy(t *testing.T) {
	now := time.Now()
	a := &agent{
		localProxyOn:             true,
		daeSubID:                 "sub-1",
		ipv4RecheckEvery:         30 * time.Minute,
		subscriptionRefreshEvery: 6 * time.Hour,
		lastIPv4Recheck:          now.Add(-31 * time.Minute),
		lastSubscriptionRefresh:  now.Add(-7 * time.Hour),
	}
	if !a.subscriptionRefreshDue() || !a.ipv4RecheckDue() {
		t.Fatal("overdue checks were not scheduled")
	}
	a.lastIPv4Recheck, a.lastSubscriptionRefresh = now, now
	if a.subscriptionRefreshDue() || a.ipv4RecheckDue() {
		t.Fatal("fresh checks were scheduled too early")
	}
	a.localProxyOn = false
	a.lastIPv4Recheck = now.Add(-time.Hour)
	a.lastSubscriptionRefresh = now.Add(-24 * time.Hour)
	if a.subscriptionRefreshDue() || a.ipv4RecheckDue() {
		t.Fatal("disabled proxy still scheduled subscription work")
	}
}

func TestSafeDaeErrorCodeAllowlist(t *testing.T) {
	for _, code := range []string{"dae_native_count_unavailable", "dae_reload_failed", "subscription_fetch_failed"} {
		if !safeDaeErrorCode(code) {
			t.Errorf("safe helper error code %q was rejected", code)
		}
	}
	for _, code := range []string{"", "provider token secret", "https://provider.invalid/sub?token=x"} {
		if safeDaeErrorCode(code) {
			t.Errorf("unsafe helper error code %q was accepted", code)
		}
	}
}
