package rules

import (
	"testing"
	"time"
	"tygateway/internal/model"
)

func TestPolicyOverridesPreferencesAndExpiry(t *testing.T) {
	e := New()
	future := time.Now().Add(time.Hour)
	d := model.Device{Profile: ProfileGFW, CustomerOverrideAction: "PROXY", CustomerOverrideUntil: &future}
	ns := []model.Node{{ID: "node-a", Group: "HK"}}
	prefs := map[string]string{"GFW": "node-a"}
	input := []model.Rule{{ID: "user", Source: "customer", SourceType: "user", MatchType: "domain", MatchValue: "example.com", Action: "BLOCK", Enabled: true}}
	policy := Policy(d, input, prefs, ns, true)
	google := e.ExplainPolicy(d.Profile, policy, Query{Domain: "google.com"})
	if google.Matched == nil || google.Matched.Action != "NODE:node-a" {
		t.Fatalf("enabled profile did not apply the category node: %#v", google)
	}
	if e.ExplainPolicy(d.Profile, policy, Query{Domain: "example.com"}).Matched.Action != "BLOCK" {
		t.Fatal("user rule was not preserved")
	}
	if e.ExplainPolicy(d.Profile, policy, Query{IsManagement: true}).Matched.Action != "DIRECT" {
		t.Fatal("management protection lost")
	}
	if e.ExplainPolicy(d.Profile, policy, Query{IP: "10.23.43.1"}).Matched.Action != "DIRECT" {
		t.Fatal("LAN protection lost")
	}
	base := Policy(d, input, prefs, ns, false)
	if e.ExplainPolicy(d.Profile, base, Query{Domain: "google.com"}).Matched.Action != "PROXY" {
		t.Fatal("inactive customer switch should not alter the base template")
	}
	if e.ExplainPolicy(d.Profile, base, Query{Domain: "example.com"}).Matched.Action != "BLOCK" {
		t.Fatal("base rules missing")
	}
	past := time.Now().Add(-time.Hour)
	d.CustomerOverrideUntil = &past
	if got := e.ExplainPolicy(d.Profile, Policy(d, input, prefs, ns, true), Query{Domain: "google.com"}); got.Matched == nil || got.Matched.Action != "DIRECT" {
		t.Fatalf("expired switch did not fail closed to direct: %#v", got)
	}
	compiled := e.CompilePolicy(policy)
	for _, rule := range compiled {
		if rule.RuleID == "temporary-override" {
			t.Fatal("global enable was incorrectly compiled as a catch-all proxy rule")
		}
	}
}

func TestApplyNodePreferencesReachesBasePolicy(t *testing.T) {
	e := New()
	d := model.Device{Profile: ProfileGFW}
	ns := []model.Node{{ID: "node-a", Group: "HK"}}
	base := Policy(d, nil, nil, ns, false)
	base = ApplyNodePreferences(base, map[string]string{"GFW": "node-a"}, ns)
	got := e.ExplainPolicy(d.Profile, base, Query{Domain: "google.com"})
	if got.Matched == nil || got.Matched.Action != "NODE:node-a" {
		t.Fatalf("base policy did not carry selected node: %#v", got)
	}
	user := model.Rule{ID: "user", SourceType: "user", MatchType: "domain", MatchValue: "example.com", Action: "BLOCK", Enabled: true}
	withUser := ApplyNodePreferences(append(base, user), map[string]string{"GFW": "node-a"}, ns)
	if got := e.ExplainPolicy(d.Profile, withUser, Query{Domain: "example.com"}); got.Matched == nil || got.Matched.Action != "BLOCK" {
		t.Fatalf("customer rule was overwritten by category preference: %#v", got)
	}
}

func TestServiceRulesPrecedeChinaEvenWhenChinaHasLowerPriority(t *testing.T) {
	e := New()
	policy := []model.Rule{
		{ID: "china", SourceType: "provider", Category: "China", MatchType: "domain_suffix", MatchValue: "example.com", Action: "DIRECT", Priority: 1, Enabled: true},
		{ID: "ai", SourceType: "provider", Category: "AI", MatchType: "domain_suffix", MatchValue: "ai.example.com", Action: "PROXY", Priority: 900, Enabled: true},
	}
	got := e.ExplainPolicy("managed_geo", policy, Query{Domain: "ai.example.com"})
	if got.Matched == nil || got.Matched.RuleID != "ai" {
		t.Fatalf("broad China rule intercepted specific service: %#v", got)
	}
}

func TestRegionAndFailoverPreferencesReachCompiledPolicy(t *testing.T) {
	e := New()
	nodes := []model.Node{{ID: "a", Name: "ALI-HK(香港1)"}, {ID: "b", Name: "ORC-US(美国4)"}}
	base := []model.Rule{{ID: "ai", SourceType: "provider", Category: "AI", MatchType: "domain_suffix", MatchValue: "ai.example.com", Action: "PROXY", Enabled: true}}
	region := e.CompilePolicy(ApplyNodePreferences(base, map[string]string{"AI": "@region:HK"}, nodes))
	if region[0].Action != "REGION:HK" {
		t.Fatalf("region choice lost: %#v", region)
	}
	backup := e.CompilePolicy(ApplyNodePreferences(base, map[string]string{"AI": "@failover:a,b"}, nodes))
	if backup[0].Action != "FAILOVER:a,b" {
		t.Fatalf("failover choice lost: %#v", backup)
	}
}
