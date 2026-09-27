package rules

import (
	"testing"
	"tygateway/internal/model"
)

func TestOrderMatchesExplanationAndResistsPollutedGeoIP(t *testing.T) {
	e := New()
	got := e.Explain(ProfileGFW, nil, Query{Domain: "google.com", CountryCode: "CN"})
	if got.Matched == nil || got.Matched.Action != "PROXY" {
		t.Fatal("GeoIP overrode domain")
	}
	rs := []model.Rule{{ID: "custom", SourceType: "user", MatchType: "domain", MatchValue: "google.com", Action: "BLOCK", Priority: 10000, Enabled: true}}
	got = e.Explain(ProfileGFW, rs, Query{Domain: "google.com"})
	if got.Matched == nil || got.Matched.RuleID != "custom" {
		t.Fatal("user priority lost")
	}
	compiled := e.Compile(ProfileGFW, rs)
	if len(compiled) < 3 || compiled[2].RuleID != "custom" {
		t.Fatal("compile disagrees with explanation")
	}
	rs[0].Enabled = false
	for _, r := range e.Compile(ProfileGFW, rs) {
		if r.RuleID == "custom" {
			t.Fatal("disabled rule compiled")
		}
	}
}
