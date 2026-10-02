package main

import (
	"testing"
	"time"

	"tygateway/internal/nodeprobe"
)

func TestProbeWarmupRequiresDistinctSeparatedNativeChecks(t *testing.T) {
	since := time.Date(2026, 10, 2, 4, 0, 0, 0, time.UTC)
	obs := func(name string, seconds int, ms int64) nodeprobe.Observation {
		return nodeprobe.Observation{Name: name, Status: "ok", LatencyMS: &ms, CheckedAt: since.Add(time.Duration(seconds) * time.Second)}
	}
	p := newWarmedProbeResults(since, map[string]bool{"hk": true, "tw": true})
	first := obs("hk", 1, 189)
	p.collect([]nodeprobe.Observation{obs("hk", -1, 10), obs("foreign", 1, 1), first, obs("tw", 1, 244)})
	if len(p.results) != 0 {
		t.Fatal("warm-up, foreign, or previous-generation result was published")
	}
	p.collect([]nodeprobe.Observation{first, first, obs("hk", 2, 43)})
	if len(p.results) != 0 {
		t.Fatal("replay/burst counted as a measured round")
	}
	// Reverse-ordered journal rows must still use the latest real observation,
	// even when it is higher than the preceding result.
	p.collect([]nodeprobe.Observation{obs("hk", 7, 72), obs("tw", 6, 68), obs("hk", 6, 43), first})
	if len(p.results) != 2 || *p.results["hk"].LatencyMS != 72 || *p.results["tw"].LatencyMS != 68 || !p.results["hk"].CheckedAt.Equal(since.Add(7*time.Second)) {
		t.Fatalf("wrong measured result: %#v", p.results)
	}
}

func TestProbeWarmupFailureIsRealAndRecoveryNeedsNewWarmup(t *testing.T) {
	since := time.Now().UTC()
	ms := int64(40)
	ok := func(seconds int) nodeprobe.Observation {
		return nodeprobe.Observation{Name: "node", Status: "ok", LatencyMS: &ms, CheckedAt: since.Add(time.Duration(seconds) * time.Second)}
	}
	p := newWarmedProbeResults(since, map[string]bool{"node": true})
	p.collect([]nodeprobe.Observation{ok(1), ok(6)})
	failed := nodeprobe.Observation{Name: "node", Status: "failed", LatencyMS: &ms, CheckedAt: since.Add(7 * time.Second)}
	p.collect([]nodeprobe.Observation{failed})
	if p.results["node"].Status != "failed" || p.results["node"].LatencyMS != nil {
		t.Fatal("new failure hidden by an earlier success")
	}
	p.collect([]nodeprobe.Observation{ok(8)})
	if len(p.results) != 0 {
		t.Fatal("recovery skipped warm-up")
	}
	p.collect([]nodeprobe.Observation{ok(12)})
	if len(p.results) != 0 {
		t.Fatal("recovery measured too soon")
	}
	p.collect([]nodeprobe.Observation{ok(13)})
	if p.results["node"].Status != "ok" || *p.results["node"].LatencyMS != 40 {
		t.Fatal("separated recovery result lost")
	}
}

func TestProbeWarmupRejectsInvalidAndDoesNotInventMissingSecondRound(t *testing.T) {
	since := time.Now().UTC()
	p := newWarmedProbeResults(since, map[string]bool{"one": true, "missing": true, "failed": true})
	negative := int64(-1)
	p.collect([]nodeprobe.Observation{
		{Name: "one", Status: "ok", CheckedAt: since.Add(time.Second)},
		{Name: "one", Status: "ok", LatencyMS: &negative, CheckedAt: since.Add(time.Second)},
		{Name: "one", Status: "unknown", CheckedAt: since.Add(time.Second)},
	})
	ms := int64(0)
	p.collect([]nodeprobe.Observation{
		{Name: "one", Status: "ok", LatencyMS: &ms, CheckedAt: since.Add(time.Second)},
		{Name: "failed", Status: "failed", CheckedAt: since.Add(time.Second)},
	})
	if len(p.results) != 1 || p.results["failed"].Status != "failed" {
		t.Fatal("missing second round was published as success or zero")
	}
	p.collect([]nodeprobe.Observation{{Name: "one", Status: "ok", LatencyMS: &ms, CheckedAt: since.Add(6 * time.Second)}})
	if got, ok := p.results["one"]; !ok || got.LatencyMS == nil || *got.LatencyMS != 0 {
		t.Fatal("genuine sub-millisecond measured result rejected")
	}
}
