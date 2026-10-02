package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"tygateway/internal/nodeprobe"
)

type probeEnvironment struct {
	config, marker string
	window         time.Duration
	run            func(context.Context, string, ...string) ([]byte, error)
	collect        func(context.Context, time.Time) ([]nodeprobe.Observation, error)
}

func probeEnvironmentDefault() probeEnvironment {
	return probeEnvironment{config: configPath, marker: managedDir + "/node-probe-restore.json", window: 40 * time.Second, run: run, collect: collectNativeChecks}
}

type probeRestore struct {
	Original      []byte `json:"original"`
	CandidateHash string `json:"candidate_hash"`
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
	deadline := time.Now().Add(env.window)
	latest := map[string]nodeprobe.Observation{}
	for {
		batch, readErr := env.collect(ctx, since)
		if readErr != nil {
			return nil, errors.New("dae check journal unavailable")
		}
		for _, obs := range batch {
			if names[obs.Name] && !obs.CheckedAt.Before(since) && (latest[obs.Name].CheckedAt.IsZero() || obs.CheckedAt.After(latest[obs.Name].CheckedAt)) {
				latest[obs.Name] = obs
			}
		}
		if len(latest) == len(names) || time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	for _, name := range req.Names {
		if obs, ok := latest[name]; ok {
			observations = append(observations, obs)
		}
	}
	return observations, nil
}

func collectNativeChecks(ctx context.Context, since time.Time) ([]nodeprobe.Observation, error) {
	return collectNativeChecksWith(ctx, since, run)
}

func collectNativeChecksWith(ctx context.Context, since time.Time, command daeCommandRunner) ([]nodeprobe.Observation, error) {
	// Filter before applying the limit. Busy DEBUG traffic must not evict health
	// checks from the bounded slice, and traffic records need not leave journald.
	out, err := command(ctx, "/usr/bin/journalctl", "-b", "-u", "dae", "--since", "@"+strconv.FormatInt(since.Unix(), 10), "--grep", "Connectivity Check", "-o", "json", "--no-pager", "-n", "2000")
	if err != nil {
		// journalctl --grep returns 1 when there are no matches. That is a
		// normal observation window, not a service/read failure.
		var exit interface{ ExitCode() int }
		if errors.As(err, &exit) && exit.ExitCode() == 1 && len(bytes.TrimSpace(out)) == 0 {
			return nil, nil
		}
		return nil, err
	}
	var result []nodeprobe.Observation
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
		if obs, ok := nodeprobe.ParseMessage(entry.Message, at); ok {
			result = append(result, obs)
		}
	}
	return result, nil
}
