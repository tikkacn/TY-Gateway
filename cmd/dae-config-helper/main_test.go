package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tygateway/internal/model"
)

func TestDaeStatusDoesNotQueueBehindPolicyApply(t *testing.T) {
	applyMu.Lock()
	defer applyMu.Unlock()

	done := make(chan applyResponse, 1)
	go func() {
		done <- apply(applyRequest{ServiceAction: "status"})
	}()

	select {
	case got := <-done:
		if got.Status != "ok" {
			t.Fatalf("status probe returned %#v", got)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("read-only DAE status probe waited on the configuration apply lock")
	}
}

func TestEnsureDaeActiveRestoresOnlyRequestedProxy(t *testing.T) {
	inactive := errors.New("inactive")
	for _, tc := range []struct {
		name       string
		persist    bool
		allowStart bool
		responses  []error
		wantCalls  string
		wantError  bool
	}{
		{"already active", true, true, []error{nil, nil}, "enable,is-active", false},
		{"direct stays stopped", false, false, []error{inactive}, "is-active", true},
		{"proxy starts", true, true, []error{nil, inactive, nil, nil}, "enable,is-active,start,is-active", false},
		{"temporary inventory probe", false, true, []error{inactive, nil, nil}, "is-active,start,is-active", false},
		{"enable fails", true, true, []error{inactive}, "enable", true},
		{"start fails", true, true, []error{nil, inactive, inactive}, "enable,is-active,start", true},
		{"start does not become active", true, true, []error{nil, inactive, nil, inactive}, "enable,is-active,start,is-active", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			runner := func(_ context.Context, path string, args ...string) ([]byte, error) {
				if path != "/usr/bin/systemctl" || len(args) == 0 {
					t.Fatalf("unexpected command: %s %v", path, args)
				}
				calls = append(calls, args[0])
				if len(calls) > len(tc.responses) {
					t.Fatal("too many commands")
				}
				return nil, tc.responses[len(calls)-1]
			}
			err := ensureDaeActive(context.Background(), tc.persist, tc.allowStart, runner)
			if (err != nil) != tc.wantError || strings.Join(calls, ",") != tc.wantCalls {
				t.Fatalf("calls=%v err=%v; want calls=%s error=%t", calls, err, tc.wantCalls, tc.wantError)
			}
		})
	}
}

func TestReadSnapshotAllowsLargeManagedRulesButKeepsBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.dae")
	content := []byte(strings.Repeat("x", 3<<20))
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSnapshot(path, 1<<20); err == nil {
		t.Fatal("small snapshot limit accepted large rules")
	}
	snapshot, err := readSnapshot(path, 16<<20)
	if err != nil || !snapshot.exists || len(snapshot.data) != len(content) {
		t.Fatalf("large managed rules could not be read: size=%d err=%v", len(snapshot.data), err)
	}
}

func TestEnsureIncludeIsIdempotentAndAvoidsCommentedText(t *testing.T) {
	config := []byte("global {}\n# include {\n#   /etc/dae/ty-gateway/managed.dae\n# }\nrouting {}\n")
	updated, changed := ensureInclude(config, managedPath)
	if !changed || !includeIsActive(string(updated), managedPath) {
		t.Fatalf("managed include was not inserted:\n%s", updated)
	}
	updatedAgain, changedAgain := ensureInclude(updated, managedPath)
	if changedAgain || string(updatedAgain) != string(updated) {
		t.Fatalf("managed include insertion is not idempotent:\n%s", updatedAgain)
	}
}

func TestManagedSubscriptionConfigContainsNoProviderURL(t *testing.T) {
	config := managedConfig(true, false, "")
	if !strings.Contains(config, "file://ty-gateway/subscription.raw") {
		t.Fatalf("dae is not configured to parse the local staged subscription: %q", config)
	}
	if strings.Contains(config, "https://") || strings.Contains(config, "token=") {
		t.Fatalf("managed dae config contains a provider URL: %q", config)
	}
	if got := managedConfig(false, false, ""); strings.Contains(got, "subscription {") {
		t.Fatalf("unbound configuration retains subscription block: %q", got)
	}
	if strings.Contains(config, "log_level: debug") || strings.Contains(config, nativeCountGroupPrefix) {
		t.Fatalf("stable config retained temporary node-count diagnostics: %q", config)
	}
}

func TestDebugCountConfigUsesUnreferencedDaeGroup(t *testing.T) {
	probeGroup := nativeCountGroupPrefix + "123456"
	config := managedConfig(true, true, probeGroup)
	if !strings.Contains(config, "filter: subtag(ty_gateway)") {
		t.Fatalf("temporary config does not use the native subscription group: %q", config)
	}
	if strings.Contains(config, "log_level: debug") {
		t.Fatalf("temporary logger override must stay in the main config only: %q", config)
	}
	if !strings.Contains(config, probeGroup) {
		t.Fatalf("temporary config is missing the count-only group: %q", config)
	}
	if strings.Contains(config, "fallback: "+probeGroup) || strings.Contains(config, "-> "+probeGroup) {
		t.Fatalf("diagnostic group unexpectedly changes traffic routing: %q", config)
	}
}

func TestNativeNodeCountProbeRunsForFreshAndCachedProxyPolicies(t *testing.T) {
	sub := &model.DaeSubscription{ID: "sub-1"}
	for _, tc := range []struct {
		name string
		has  bool
		req  applyRequest
		want bool
	}{
		{name: "fresh subscription", has: true, req: applyRequest{ManageSubscription: true, Subscription: sub}, want: true},
		{name: "cached subscription on enable", has: true, req: applyRequest{Policy: &model.DaePolicy{ProxyEnabled: true}}, want: true},
		{name: "direct-only cached policy", has: true, req: applyRequest{Policy: &model.DaePolicy{ProxyEnabled: false}}},
		{name: "proxy without staged payload", req: applyRequest{Policy: &model.DaePolicy{ProxyEnabled: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldProbeNativeNodeCount(tc.has, tc.req); got != tc.want {
				t.Fatalf("shouldProbeNativeNodeCount() = %t; want %t", got, tc.want)
			}
		})
	}
}

func TestSetGlobalLogLevelOnlyChangesTheTopLevelGlobal(t *testing.T) {
	config := []byte("include {\n  /etc/dae/managed.dae\n}\n\nglobal {\n  log_level: info # keep-note\n  auto_config_kernel_parameter: false\n}\nrouting {\n  # log_level: trace\n}\n")
	updated, err := setGlobalLogLevel(config, "debug")
	if err != nil {
		t.Fatal(err)
	}
	text := string(updated)
	if !strings.Contains(text, "log_level: debug # keep-note") {
		t.Fatalf("did not preserve the global field comment: %s", text)
	}
	if !strings.Contains(text, "# log_level: trace") {
		t.Fatalf("modified a commented non-global field: %s", text)
	}
	stable, err := setGlobalLogLevel([]byte("routing {}\n"), "info")
	if err != nil || !strings.HasPrefix(string(stable), "global {\n  log_level: info\n}") {
		t.Fatalf("could not add a global log level: %s, err=%v", stable, err)
	}
	if _, err := setGlobalLogLevel(config, "verbose"); err == nil {
		t.Fatal("accepted an unsupported Dae log level")
	}
}

func TestParseNativeDaeGroupCount(t *testing.T) {
	probeGroup := nativeCountGroupPrefix + "123456"
	logs := []byte("DEBU Group \"" + probeGroup + "\" node list:\nDEBU \tnode one\nDEBU \tnode two\nINFO next control-plane step\n")
	got, ok := parseNativeGroupNodeCount(logs, probeGroup)
	if !ok || got != 2 {
		t.Fatalf("got count=%d ok=%v; want completed native Dae group count 2", got, ok)
	}
	if _, ok := parseNativeGroupNodeCount([]byte("DEBU Group \"other\" node list:\nDEBU \tnode\nINFO next control-plane step\n"), probeGroup); ok {
		t.Fatal("accepted a count from a different Dae group")
	}
	if got, ok := parseNativeGroupNodeCount([]byte("DEBU Group \""+probeGroup+"\" node list:\nDEBU \tnode one\n"), probeGroup); ok || got != 1 {
		t.Fatalf("partial snapshot was considered complete: count=%d ok=%v", got, ok)
	}
	if got, ok := parseNativeGroupNodeCount([]byte("DEBU Group \""+probeGroup+"\" node list:\nDEBU \t<Empty>\nINFO next control-plane step\n"), probeGroup); !ok || got != 0 {
		t.Fatalf("got empty group count=%d ok=%v; want completed zero-node result", got, ok)
	}
	names, ok := parseNativeGroupNodeNames([]byte("DEBU Group \""+probeGroup+"\" node list:\nDEBU \tSingapore\nDEBU \t日本\nINFO next control-plane step\n"), probeGroup)
	if !ok || len(names) != 2 || names[0] != "Singapore" || names[1] != "日本" {
		t.Fatalf("dae node names were not preserved exactly: %#v ok=%t", names, ok)
	}
}

func TestSubscriptionIDValidation(t *testing.T) {
	for _, id := range []string{"sub-123", "A_B9", ""} {
		if (id != "") != validSubscriptionID(id) {
			t.Errorf("validSubscriptionID(%q) returned an unexpected result", id)
		}
	}
	for _, id := range []string{"../other", "a/b", "contains space", strings.Repeat("a", 129)} {
		if validSubscriptionID(id) {
			t.Errorf("accepted unsafe subscription id %q", id)
		}
	}
}
