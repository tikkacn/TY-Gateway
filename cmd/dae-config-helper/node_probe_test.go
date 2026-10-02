package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tygateway/internal/nodeprobe"
)

type probeJournalExit int

func (e probeJournalExit) Error() string { return "journal exit" }
func (e probeJournalExit) ExitCode() int { return int(e) }

func TestProbeJournalFiltersTrafficBeforeLimitAndHandlesEmptyWindows(t *testing.T) {
	since := time.Now().UTC().Truncate(time.Second)
	line, _ := json.Marshal(map[string]string{"MESSAGE": `DEBUG Connectivity Check last=74ms network=tcp4 node=test`, "__REALTIME_TIMESTAMP": strconv.FormatInt(since.Add(time.Millisecond).UnixMicro(), 10)})
	for _, test := range []struct {
		name      string
		output    []byte
		err       error
		wantError bool
		count     int
	}{
		{"checks", line, nil, false, 1},
		{"no matches", nil, probeJournalExit(1), false, 0},
		{"read error", nil, probeJournalExit(2), true, 0},
		{"exit with diagnostic", []byte("permission denied"), probeJournalExit(1), true, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := collectNativeChecksWith(context.Background(), since, func(_ context.Context, path string, args ...string) ([]byte, error) {
				if path != "/usr/bin/journalctl" || !strings.Contains(strings.Join(args, "|"), "--grep|Connectivity Check") || !strings.Contains(strings.Join(args, "|"), "-n|2000") {
					t.Fatalf("unbounded or unfiltered journal command: %s %v", path, args)
				}
				return test.output, test.err
			})
			if (err != nil) != test.wantError || len(got) != test.count {
				t.Fatalf("got=%v err=%v", got, err)
			}
		})
	}
}

func TestProbeRestoresOriginalConfigOnSuccessAndFailure(t *testing.T) {
	for _, fault := range []string{"", "validate", "reload", "journal"} {
		t.Run(fault, func(t *testing.T) {
			dir := t.TempDir()
			original := []byte("global {\n  log_level: info\n}\n")
			env := probeEnvironment{config: filepath.Join(dir, "config.dae"), marker: filepath.Join(dir, "restore.json"), window: time.Nanosecond}
			if err := atomicWrite(env.config, original, 0600); err != nil {
				t.Fatal(err)
			}
			reloads := 0
			env.run = func(_ context.Context, path string, args ...string) ([]byte, error) {
				if strings.HasSuffix(path, "/dae") {
					candidate, _ := os.ReadFile(env.config)
					if !strings.Contains(string(candidate), "check_interval: 5s") {
						t.Fatal("manual check retains the long periodic delay")
					}
				}
				if strings.HasSuffix(path, "/dae") && fault == "validate" {
					return nil, errors.New("bad config")
				}
				if len(args) > 0 && args[0] == "reload" {
					reloads++
					if reloads == 1 && fault == "reload" {
						return nil, errors.New("reload failed")
					}
				}
				return nil, nil
			}
			env.collect = func(_ context.Context, since time.Time) ([]nodeprobe.Observation, error) {
				if fault == "journal" {
					return nil, errors.New("journal unavailable")
				}
				ms := int64(46)
				return []nodeprobe.Observation{{Name: "香港 节点", Status: "ok", LatencyMS: &ms, CheckedAt: since.Add(time.Millisecond)}}, nil
			}
			obs, err := runNodeProbe(context.Background(), nodeprobe.Request{Names: []string{"香港 节点", "未观测节点"}}, env)
			if (err != nil) != (fault != "") {
				t.Fatalf("fault=%q err=%v", fault, err)
			}
			if fault == "" && (len(obs) != 1 || *obs[0].LatencyMS != 46) {
				t.Fatalf("unknown node was invented: %#v", obs)
			}
			current, _ := os.ReadFile(env.config)
			if !bytes.Equal(current, original) {
				t.Fatal("log config not restored")
			}
			if _, err := os.Stat(env.marker); !os.IsNotExist(err) {
				t.Fatal("restore marker not removed")
			}
		})
	}
}

func TestProbeDiagnosticConfigSupportsBootstrapInlineGlobal(t *testing.T) {
	for _, original := range []string{"global {}\ninclude { other.dae }\n", "global { } # bootstrap\ninclude { other.dae }\n", "global {\n  log_level: info\n  check_interval: 30s\n}\ninclude { other.dae }\n"} {
		debug, err := setGlobalLogLevel([]byte(original), "debug")
		if err != nil {
			t.Fatal(err)
		}
		debug, err = setDiagnosticGlobalField(debug, "check_interval", "5s")
		if err != nil || strings.Count(string(debug), "global {") != 1 || !strings.Contains(string(debug), "check_interval: 5s") || !strings.Contains(string(debug), "log_level: debug") || !strings.Contains(string(debug), "include { other.dae }") {
			t.Fatalf("invalid diagnostic bootstrap config: %s %v", debug, err)
		}
	}
}
func TestProbeNeverStartsInactiveDAE(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	env := probeEnvironment{config: filepath.Join(dir, "missing"), marker: filepath.Join(dir, "marker"), run: func(_ context.Context, path string, args ...string) ([]byte, error) {
		calls++
		if args[0] != "is-active" {
			t.Fatal("unexpected mutating command")
		}
		return nil, errors.New("inactive")
	}}
	if _, err := runNodeProbe(context.Background(), nodeprobe.Request{Names: []string{"节点"}}, env); err == nil || calls != 1 {
		t.Fatal("inactive service accepted")
	}
}
func TestProbeCrashRecoveryAndExternalChangeProtection(t *testing.T) {
	dir := t.TempDir()
	original := []byte("global {\n  log_level: info\n}\n")
	debug, _ := setGlobalLogLevel(original, "debug")
	env := probeEnvironment{config: filepath.Join(dir, "config"), marker: filepath.Join(dir, "marker"), run: func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("inactive") }}
	marker, _ := json.Marshal(probeRestore{Original: original, CandidateHash: probeHash(debug)})
	_ = atomicWrite(env.config, debug, 0600)
	_ = atomicWrite(env.marker, marker, 0600)
	if err := restoreProbeLog(env); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(env.config)
	if !bytes.Equal(got, original) {
		t.Fatal("crash recovery did not restore logging")
	}
	_ = atomicWrite(env.marker, marker, 0600)
	_ = atomicWrite(env.config, []byte("new external config"), 0600)
	if restoreProbeLog(env) == nil {
		t.Fatal("external edit overwritten")
	}
	got, _ = os.ReadFile(env.config)
	if string(got) != "new external config" {
		t.Fatal("external edit lost")
	}
}

func TestProbeRestoreReloadFailureDoesNotReturnSuccess(t *testing.T) {
	dir := t.TempDir()
	original := []byte("global {\n  log_level: info\n}\n")
	reloads := 0
	env := probeEnvironment{config: filepath.Join(dir, "config"), marker: filepath.Join(dir, "marker"), window: time.Nanosecond,
		run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if args[0] == "reload" {
				reloads++
				if reloads == 2 {
					return nil, errors.New("restore reload failed")
				}
			}
			return nil, nil
		},
		collect: func(_ context.Context, since time.Time) ([]nodeprobe.Observation, error) {
			ms := int64(3)
			return []nodeprobe.Observation{{Name: "节点", Status: "ok", LatencyMS: &ms, CheckedAt: since.Add(time.Millisecond)}}, nil
		}}
	_ = atomicWrite(env.config, original, 0600)
	obs, err := runNodeProbe(context.Background(), nodeprobe.Request{Names: []string{"节点"}}, env)
	if err == nil || obs != nil {
		t.Fatal("restore failure reported successful metrics")
	}
	if _, err := os.Stat(env.marker); err != nil {
		t.Fatal("restore retry marker lost")
	}
}
