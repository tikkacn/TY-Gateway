package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"tygateway/internal/model"
)

func waitConfigSync(t *testing.T, a *agent) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a.stateMu.RLock()
		running := a.syncRunning
		a.stateMu.RUnlock()
		if !running {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("config sync did not finish")
}

func cachedSwitchAgent(t *testing.T) *agent {
	t.Helper()
	nodes := fakeValidatedNodes(1)
	a := &agent{
		stateDir: t.TempDir(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"},
		allowDaeProxy: true, logger: log.New(io.Discard, "", 0),
		daeApplier: &fakeDaeApplier{stopped: true, result: daeApplyResult{Status: "ok", PolicyStatus: "applied", NodeCount: 1, Nodes: nodes}},
	}
	snapshot := appliedSnapshot{SubscriptionID: "sub-1", Config: model.DeviceConfig{
		Device: model.CustomerDevice{ID: "device-1"}, Profile: "gfw_precise", DaeSubscriptionManaged: true,
		Nodes: []model.Node{{ID: nodes[0].ID, Name: nodes[0].Name}},
	}, Customer: json.RawMessage(`{}`), LocalPreferences: map[string]string{"AI": nodes[0].ID}, LocalRevision: 3}
	data, _ := json.Marshal(snapshot)
	if err := writePrivateFile(a.snapshotPath(), data); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCachedEnableDoesNotContactCloud(t *testing.T) {
	a := cachedSwitchAgent(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	a.server, a.client = server.URL, server.Client()
	before, _ := os.ReadFile(a.snapshotPath())
	state := a.setLocalProxy(context.Background(), true)
	if !state.Enabled || !state.Applied || state.Initializing || state.Error != "" || requests.Load() != 0 {
		t.Fatalf("cached enable waited for Cloud: %#v requests=%d", state, requests.Load())
	}
	after, _ := os.ReadFile(a.snapshotPath())
	if string(before) != string(after) {
		t.Fatal("enable changed saved local choices")
	}
	if err := a.fetchConfig(context.Background()); err == nil {
		t.Fatal("failed cloud refresh unexpectedly succeeded")
	}
	after, _ = os.ReadFile(a.snapshotPath())
	if string(before) != string(after) || !a.localControlStatus().Applied {
		t.Fatal("failed background update disturbed working cache/proxy")
	}
}

func TestCloseDuringFirstDownloadDoesNotWaitOrReopen(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			close(started)
			<-release
			json.NewEncoder(w).Encode(model.DeviceConfig{
				Device: model.CustomerDevice{ID: "device-1"}, Profile: "gfw_precise", ServerTime: time.Now().UTC(),
				DaeSubscriptionManaged: true, DaeSubscription: &model.DaeSubscription{ID: "sub-1", URL: "https://provider.invalid"},
			})
		case strings.HasSuffix(r.URL.Path, "/customer/me"):
			io.WriteString(w, `{"device":{"id":"device-1"},"preferences":{},"nodes":[],"rules":[]}`)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	helper := &fakeDaeApplier{stopped: true, result: daeApplyResult{Status: "ok", PolicyStatus: "prepared", NodeCount: 1, Nodes: fakeValidatedNodes(1)}}
	a := &agent{server: server.URL, client: server.Client(), stateDir: t.TempDir(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, allowDaeProxy: true, daeApplier: helper, logger: log.New(io.Discard, "", 0)}
	state := a.setLocalProxy(context.Background(), true)
	if !state.Initializing || state.Enabled || state.Applied {
		t.Fatalf("pending initialization claimed enabled: %#v", state)
	}
	<-started
	done := make(chan localControlResponse, 1)
	go func() { done <- a.setLocalProxy(context.Background(), false) }()
	select {
	case state = <-done:
		if state.Enabled || state.Initializing || state.DaemonActive {
			t.Fatalf("close did not cancel pending enable: %#v", state)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("close blocked on cloud download")
	}
	close(release)
	waitConfigSync(t, a)
	state = a.localControlStatus()
	if state.Enabled || state.Initializing || state.DaemonActive || helper.policy.ProxyEnabled {
		t.Fatalf("late download reopened proxy: %#v", state)
	}
	if _, err := a.loadAppliedSnapshot(); err != nil {
		t.Fatal("canceled enable should still allow a validated direct-mode cache")
	}
	restarted := &agent{stateDir: a.stateDir}
	if err := restarted.loadLocalProxy(); err != nil || restarted.localProxyOn {
		t.Fatal("canceled enable was not persisted off")
	}
}

type syncRoundTrip func(*http.Request) (*http.Response, error)

func TestBackgroundDownloadDoesNotBlockHeartbeatAndCommands(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var heartbeats, commands atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/config"):
			close(started)
			<-release
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.HasSuffix(r.URL.Path, "/heartbeat"):
			heartbeats.Add(1)
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/commands"):
			commands.Add(1)
			io.WriteString(w, `{"commands":[]}`)
		}
	}))
	defer server.Close()
	a := &agent{server: server.URL, client: server.Client(), stateDir: t.TempDir(), state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}, backgroundSync: true, logger: log.New(io.Discard, "", 0)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.cycle(ctx); err != nil {
		close(release)
		t.Fatal(err)
	}
	<-started
	if err := a.cycle(ctx); err != nil || heartbeats.Load() != 2 || commands.Load() != 2 {
		close(release)
		t.Fatalf("control traffic blocked by config: heartbeat=%d commands=%d err=%v", heartbeats.Load(), commands.Load(), err)
	}
	close(release)
	waitConfigSync(t, a)
}

func (f syncRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type syncTimeout struct{}

func (syncTimeout) Error() string   { return "simulated network timeout" }
func (syncTimeout) Timeout() bool   { return true }
func (syncTimeout) Temporary() bool { return true }

func TestConfigRetriesOnlyTimeoutsWithFreshSignatures(t *testing.T) {
	for _, status := range []int{0, 401, 403, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			nonces := map[string]bool{}
			a := &agent{server: "https://cloud.invalid", state: credentialState{DeviceID: "device-1", DeviceSecret: "secret"}}
			a.client = &http.Client{Timeout: 15 * time.Second, Transport: syncRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				nonce := r.Header.Get("X-TY-Nonce")
				if nonces[nonce] || nonce == "" {
					t.Fatal("retry reused request signature nonce")
				}
				nonces[nonce] = true
				if status == 0 {
					return nil, syncTimeout{}
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			})}
			_, _, err := a.downloadConfig(context.Background())
			want := 1
			if status == 0 {
				want = 3
				if err == nil {
					t.Fatal("timeouts unexpectedly succeeded")
				}
			}
			if calls != want {
				t.Fatalf("attempts=%d want=%d", calls, want)
			}
		})
	}
}

func TestConfigBodyBudgetIsIndependentOfHeartbeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(80 * time.Millisecond)
		io.WriteString(w, `{}`)
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 20 * time.Millisecond
	a := &agent{server: server.URL, client: client}
	if _, _, err := a.request(context.Background(), "GET", "/config", nil); err != nil {
		t.Fatalf("config body inherited short heartbeat timeout: %v", err)
	}
	if _, _, err := a.request(context.Background(), "POST", "/heartbeat", nil); safeSyncError(err) != "timeout" {
		t.Fatalf("heartbeat timeout changed: %v", err)
	}
	if client.Timeout != 20*time.Millisecond || configDownloadTimeout != 90*time.Second {
		t.Fatal("shared client mutated or config budget changed")
	}
}
