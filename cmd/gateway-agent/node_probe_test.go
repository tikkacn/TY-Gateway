package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/nodeprobe"
)

type fakeNodeProber struct {
	fakeDaeApplier
	observations []nodeprobe.Observation
	probeCalls   int
	probeErr     error
}

func (f *fakeNodeProber) Probe(context.Context, nodeprobe.Request) ([]nodeprobe.Observation, error) {
	f.probeCalls++
	return f.observations, f.probeErr
}
func TestNodeProbeSettingsAreLocalPersistedAndDoNotEnableProxy(t *testing.T) {
	f := &fakeNodeProber{}
	a := &agent{stateDir: t.TempDir(), daeApplier: f}
	response := a.localNodeProbe(context.Background(), http.MethodPost, "/speed-test/settings", json.RawMessage(`{"url":"https://8.8.8.8/ping"}`))
	if response.Error != "" || f.calls != 0 || f.stopCalls != 0 || a.localProxyOn {
		t.Fatalf("save enabled proxy: %#v", response)
	}
	if got := a.localCheckTarget(); got != "https://8.8.8.8/ping,8.8.8.8" {
		t.Fatalf("target not persisted: %s", got)
	}
	restarted := &agent{stateDir: a.stateDir}
	if restarted.localCheckTarget() != a.localCheckTarget() {
		t.Fatal("setting lost on restart")
	}
	response = a.localNodeProbe(context.Background(), http.MethodPost, "/speed-test/run", json.RawMessage(`{}`))
	if response.Error == "" || f.probeCalls != 0 {
		t.Fatal("proxy-off probe started")
	}
	old := a.localCheckTarget()
	response = a.localNodeProbe(context.Background(), http.MethodPost, "/speed-test/settings", json.RawMessage(`{"url":"http://127.0.0.1/"}`))
	if response.Error == "" || a.localCheckTarget() != old {
		t.Fatal("invalid save changed target")
	}
	_ = os.WriteFile(filepath.Join(a.stateDir, nodeProbeFile), []byte(`{"url":"longer than the target","target":"x"}`), 0600)
	if a.localCheckTarget() != defaultNodeProbe().Target {
		t.Fatal("corrupt metrics disabled default checks")
	}
}
func TestNodeProbeRealObservationsMapOnlyToValidatedNodes(t *testing.T) {
	ms := int64(83)
	f := &fakeNodeProber{observations: []nodeprobe.Observation{{Name: "新加坡节点", Status: "ok", LatencyMS: &ms, CheckedAt: time.Now().UTC()}, {Name: "foreign", Status: "failed"}}}
	a := &agent{stateDir: t.TempDir(), state: credentialState{DeviceID: "device"}, daeApplier: f, localProxyOn: true, proxyApplied: true, policyReady: true}
	config := model.DeviceConfig{Device: model.CustomerDevice{ID: "device"}, Profile: "gfw_precise", ConfigVersion: 1, Nodes: []model.Node{{ID: "n1", Name: "新加坡节点"}, {ID: "n2", Name: "未观测"}}}
	customer := []byte(`{"device":{"id":"device","config_version":1},"nodes":[{"id":"n1","name":"新加坡节点"},{"id":"n2","name":"未观测"}]}`)
	if err := a.saveAppliedSnapshot(config, customer, "sub"); err != nil {
		t.Fatal(err)
	}
	response := a.localNodeProbe(context.Background(), http.MethodPost, "/speed-test/run", json.RawMessage(`{}`))
	if response.Error != "" {
		t.Fatal(response.Error)
	}
	var state nodeprobe.State
	_ = json.Unmarshal(response.Data, &state)
	if len(state.Results) != 2 || state.Results[0].ID != "n1" || state.Results[0].LatencyMS == nil || *state.Results[0].LatencyMS != 83 || state.Results[1].Status != "unknown" || state.Results[1].LatencyMS != nil {
		t.Fatalf("invented or wrong results: %#v", state)
	}
	response = a.localNodeProbe(context.Background(), http.MethodPost, "/speed-test/run", json.RawMessage(`{}`))
	if response.Error == "" || f.probeCalls != 1 {
		t.Fatal("cooldown missing")
	}
	a.lastProbeStarted = time.Time{}
	f.probeErr = errors.New("restore failed")
	response = a.localNodeProbe(context.Background(), http.MethodPost, "/speed-test/run", json.RawMessage(`{}`))
	if response.Error == "" {
		t.Fatal("failure accepted")
	}
	saved, _ := a.loadNodeProbe()
	if *saved.Results[0].LatencyMS != 83 {
		t.Fatal("failed measurement replaced good cache")
	}
}

func TestNodeProbeAddressApplyFailureRollsBack(t *testing.T) {
	f := &fakeNodeProber{fakeDaeApplier: fakeDaeApplier{results: []daeApplyResult{{Status: "error"}, {Status: "ok", PolicyStatus: "applied", NodeCount: 1}}}}
	a := &agent{stateDir: t.TempDir(), state: credentialState{DeviceID: "device"}, interfaceName: "eth0", daeApplier: f, localProxyOn: true, proxyApplied: true, policyReady: true}
	config := model.DeviceConfig{Device: model.CustomerDevice{ID: "device"}, Profile: "gfw_precise", ConfigVersion: 1, DaeSubscriptionManaged: true, Nodes: []model.Node{{ID: "n1", Name: "节点"}}}
	customer := []byte(`{"device":{"id":"device","config_version":1},"nodes":[{"id":"n1","name":"节点"}]}`)
	if err := a.saveAppliedSnapshot(config, customer, "sub"); err != nil {
		t.Fatal(err)
	}
	response := a.localNodeProbe(context.Background(), http.MethodPost, "/speed-test/settings", json.RawMessage(`{"url":"https://8.8.8.8/ping"}`))
	if response.Error == "" || f.calls != 2 || a.localCheckTarget() != defaultNodeProbe().Target || f.policy.TCPCheckURL != defaultNodeProbe().Target {
		t.Fatalf("failed address not rolled back: %#v calls=%d target=%s", response, f.calls, a.localCheckTarget())
	}
}
