package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"tygateway/internal/nodeprobe"
)

type probeEnvironment struct {
	config, marker string
	window         time.Duration
	run            func(context.Context, string, ...string) ([]byte, error)
	collect        func(context.Context, time.Time) (nativeProbeBatch, error)
}

type nativeProbeBatch struct {
	ReloadedAt   time.Time
	Observations []nodeprobe.Observation
}

func probeEnvironmentDefault() probeEnvironment {
	return probeEnvironment{config: configPath, marker: managedDir + "/node-probe-restore.json", window: 40 * time.Second, run: run, collect: collectNativeProbeBatch}
}

type probeRestore struct {
	Original      []byte `json:"original"`
	CandidateHash string `json:"candidate_hash"`
}

// Use a later native HTTP check, not the first connection after a reload.
// A full diagnostic check interval separates warm-up from measurement and
// prevents replayed journal entries or near-simultaneous checks from counting
// as the measured round. This does not change DAE's routing/selection policy.
const probeWarmupSeparation = 5 * time.Second

type warmedProbeResults struct {
	since   time.Time
	names   map[string]bool
	seen    map[string]time.Time
	warmAt  map[string]time.Time
	results map[string]nodeprobe.Observation
}

func newWarmedProbeResults(since time.Time, names map[string]bool) *warmedProbeResults {
	return &warmedProbeResults{since: since, names: names, seen: map[string]time.Time{}, warmAt: map[string]time.Time{}, results: map[string]nodeprobe.Observation{}}
}

func (p *warmedProbeResults) collect(batch []nodeprobe.Observation) {
	// journalctl output order is not an API guarantee. Sort a copy, and dedupe
	// by the native timestamp across polls rather than by collection time.
	ordered := append([]nodeprobe.Observation(nil), batch...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].CheckedAt.Before(ordered[j].CheckedAt) })
	for _, obs := range ordered {
		if !p.names[obs.Name] || obs.CheckedAt.Before(p.since) || !obs.CheckedAt.After(p.seen[obs.Name]) {
			continue
		}
		if obs.Status != "failed" && (obs.Status != "ok" || obs.LatencyMS == nil || *obs.LatencyMS < 0 || *obs.LatencyMS > 600000) {
			continue
		}
		p.seen[obs.Name] = obs.CheckedAt
		if obs.Status == "failed" {
			// Failure is real evidence even if warm-up never succeeded. A later
			// recovery must warm up again, not inherit an older good connection.
			delete(p.warmAt, obs.Name)
			obs.LatencyMS = nil
			p.results[obs.Name] = obs
			continue
		}
		if p.warmAt[obs.Name].IsZero() {
			p.warmAt[obs.Name] = obs.CheckedAt
			delete(p.results, obs.Name)
			continue
		}
		if obs.CheckedAt.Sub(p.warmAt[obs.Name]) >= probeWarmupSeparation {
			p.results[obs.Name] = obs // Keep the real measurement, not a minimum.
		}
	}
}

func probeHash(data []byte) string { hash := sha256.Sum256(data); return hex.EncodeToString(hash[:]) }

func restoreProbeLog(env probeEnvironment) error {
	marker, err := readSnapshot(env.marker, 2<<20)
	if err != nil {
		return errors.New("cannot read diagnostic restore marker")
	}
	if !marker.exists {
		return nil
	}
	var backup probeRestore
	if json.Unmarshal(marker.data, &backup) != nil || len(backup.Original) == 0 || len(backup.CandidateHash) != 64 {
		return errors.New("invalid diagnostic restore marker")
	}
	current, err := readSnapshot(env.config, 1<<20)
	if err != nil || !current.exists {
		return errors.New("cannot read diagnostic config")
	}
	if !bytes.Equal(current.data, backup.Original) {
		if probeHash(current.data) != backup.CandidateHash {
			return errors.New("diagnostic config changed externally; restore requires review")
		}
		if err := atomicWrite(env.config, backup.Original, 0600); err != nil {
			return errors.New("cannot restore diagnostic log level")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	// Never start a service that the user (or a failure) has stopped.
	if _, err := env.run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dae"); err == nil {
		if _, err := env.run(ctx, "/usr/bin/systemctl", "reload", "dae"); err != nil {
			return errors.New("diagnostic log-level reload failed")
		}
	}
	if err := os.Remove(env.marker); err != nil {
		return errors.New("cannot finish diagnostic restore")
	}
	return nil
}

func runNodeProbe(ctx context.Context, req nodeprobe.Request, env probeEnvironment) (observations []nodeprobe.Observation, err error) {
	if len(req.Names) == 0 || len(req.Names) > 256 {
		return nil, errors.New("invalid probe inventory")
	}
	names := map[string]bool{}
	for _, name := range req.Names {
		if name == "" || len(name) > 512 || strings.ContainsAny(name, "\r\n\x00") || names[name] || strings.Contains(strings.ToLower(name), "ipv6") {
			return nil, errors.New("invalid probe node")
		}
		names[name] = true
	}
	if err := restoreProbeLog(env); err != nil {
		return nil, err
	}
	if _, err := env.run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dae"); err != nil {
		return nil, errors.New("dae must already be active")
	}
	original, err := readSnapshot(env.config, 1<<20)
	if err != nil || !original.exists {
		return nil, errors.New("dae config unavailable")
	}
	debug, err := setGlobalLogLevel(original.data, "debug")
	if err != nil {
		return nil, err
	}
	// Warm reloads defer their first check by check_interval. Shorten that
	// delay only for this manual observation; the exact original is restored.
	debug, err = setDiagnosticGlobalField(debug, "check_interval", "5s")
	if err != nil {
		return nil, err
	}
	backup, _ := json.Marshal(probeRestore{Original: original.data, CandidateHash: probeHash(debug)})
	if err := atomicWrite(env.marker, backup, 0600); err != nil {
		return nil, err
	}
	defer func() {
		if restoreErr := restoreProbeLog(env); restoreErr != nil {
			observations, err = nil, restoreErr // Never call a partial/unsafe run successful.
		}
	}()
	if err := atomicWrite(env.config, debug, 0600); err != nil {
		return nil, err
	}
	if _, err := env.run(ctx, "/usr/bin/dae", "validate", "-c", env.config); err != nil {
		return nil, errors.New("diagnostic config validation failed")
	}
	since := time.Now().UTC()
	if _, err := env.run(ctx, "/usr/bin/systemctl", "reload", "dae"); err != nil {
		return nil, errors.New("diagnostic reload failed")
	}
	// The new generation can check immediately after becoming ready, before
	// ExecReload's compatibility hook returns. Use DAE's completion record,
	// not the later systemctl return time, or that first warm-up gets lost.
	deadline := time.Now().Add(env.window)
	var warmed *warmedProbeResults
	for {
		batch, readErr := env.collect(ctx, since)
		if readErr != nil {
			return nil, errors.New("dae check journal unavailable")
		}
		if warmed == nil && !batch.ReloadedAt.IsZero() && !batch.ReloadedAt.Before(since) {
			warmed = newWarmedProbeResults(batch.ReloadedAt, names)
		}
		if warmed != nil {
			warmed.collect(batch.Observations)
		}
		if warmed != nil && len(warmed.results) == len(names) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	if warmed == nil {
		return nil, errors.New("completed diagnostic generation was not observed")
	}
	for _, name := range req.Names {
		if obs, ok := warmed.results[name]; ok {
			observations = append(observations, obs)
		}
	}
	return observations, nil
}

func collectNativeProbeBatch(ctx context.Context, since time.Time) (nativeProbeBatch, error) {
	return collectNativeProbeBatchWith(ctx, since, run)
}

func collectNativeChecksWith(ctx context.Context, since time.Time, command daeCommandRunner) ([]nodeprobe.Observation, error) {
	batch, err := collectNativeProbeBatchWith(ctx, since, command)
	return batch.Observations, err
}

var probeANSI = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var probeReloadFinished = regexp.MustCompile(`(?:^\s*(?:INFO(?:\[[^]]*\])?[ \t]+)?|(?:^|\s)msg=")(?:\[Reload\]|Reload:)[ \t]+Finished(?:[ \t]|"|$)`)

func collectNativeProbeBatchWith(ctx context.Context, since time.Time, command daeCommandRunner) (nativeProbeBatch, error) {
	// Filter before applying the limit. Busy DEBUG traffic must not evict health
	// checks from the bounded slice, and traffic records need not leave journald.
	out, err := command(ctx, "/usr/bin/journalctl", "-b", "-u", "dae", "--since", "@"+strconv.FormatInt(since.Unix(), 10), "--grep", "Connectivity Check|Reload", "-o", "json", "--no-pager", "-n", "2000")
	if err != nil {
		// journalctl --grep returns 1 when there are no matches. That is a
		// normal observation window, not a service/read failure.
		var exit interface{ ExitCode() int }
		if errors.As(err, &exit) && exit.ExitCode() == 1 && len(bytes.TrimSpace(out)) == 0 {
			return nativeProbeBatch{}, nil
		}
		return nativeProbeBatch{}, err
	}
	var result nativeProbeBatch
	for _, line := range bytes.Split(out, []byte{'\n'}) {
		var entry struct {
			Message string `json:"MESSAGE"`
			Stamp   string `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		stamp, err := strconv.ParseInt(entry.Stamp, 10, 64)
		if err != nil {
			continue
		}
		at := time.UnixMicro(stamp).UTC()
		if at.Before(since) {
			continue
		}
		message := probeANSI.ReplaceAllString(entry.Message, "")
		if probeReloadFinished.MatchString(message) && (result.ReloadedAt.IsZero() || at.Before(result.ReloadedAt)) {
			result.ReloadedAt = at
		}
		if obs, ok := nodeprobe.ParseMessage(message, at); ok {
			result.Observations = append(result.Observations, obs)
		}
	}
	return result, nil
}
