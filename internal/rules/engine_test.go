package rules

import (
	"testing"
	"tygateway/internal/model"
)

func TestGFWProfileAndUserOverlay(t *testing.T) {
	e := New()
	base := e.Explain(ProfileGFW, nil, Query{Domain: "google.com"})
	if base.Matched == nil || base.Matched.Action != "PROXY" {
		t.Fatalf("google should proxy: %#v", base)
	}
	custom := []model.Rule{{ID: "u1", Source: "user", SourceType: "user", MatchType: "domain_suffix", MatchValue: "google.com", Action: "DIRECT", Enabled: true}}
	overlay := e.Explain(ProfileGFW, custom, Query{Domain: "www.google.com"})
	if overlay.Matched == nil || overlay.Matched.Action != "DIRECT" {
		t.Fatalf("user overlay should win: %#v", overlay)
	}
	cn := e.Explain(ProfileGFW, nil, Query{Domain: "baidu.com"})
	if cn.Matched == nil || cn.Matched.Action != "DIRECT" {
		t.Fatalf("cn should direct: %#v", cn)
	}
}

func TestCustomerIPRulesMatchIPv4AndIPv6(t *testing.T) {
	e := New()
	rules := []model.Rule{
		{ID: "v4-net", Source: "customer", SourceType: "user", MatchType: "cidr", MatchValue: "192.0.2.0/24", Action: "DIRECT", Enabled: true},
		{ID: "v6-ip", Source: "customer", SourceType: "user", MatchType: "ip", MatchValue: "2001:db8::1", Action: "BLOCK", Enabled: true},
	}

	for _, tc := range []struct {
		name string
		ip   string
		want string
	}{
		{name: "IPv4 CIDR", ip: "192.0.2.42", want: "DIRECT"},
		{name: "IPv6 literal", ip: "2001:db8::1", want: "BLOCK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := e.Explain(ProfileGFW, rules, Query{IP: tc.ip})
			if got.Matched == nil || got.Matched.Action != tc.want {
				t.Fatalf("IP rule did not match %s: %#v", tc.ip, got)
			}
		})
	}
}

func TestCustomerChoiceOverridesAdministratorBaseline(t *testing.T) {
	engine := New()
	baseline := model.Rule{ID: "admin", Source: "admin", SourceType: "admin", MatchType: "domain_suffix", MatchValue: "example.org", Action: "PROXY", Priority: 1, Enabled: true}
	legacyBaseline := model.Rule{ID: "legacy", Source: "user", SourceType: "user", MatchType: "domain_suffix", MatchValue: "legacy.example", Action: "PROXY", Priority: 1, Enabled: true}
	choice := model.Rule{ID: "customer", Source: "customer", SourceType: "user", MatchType: "domain_suffix", MatchValue: "example.org", Action: "DIRECT", Priority: 100, Enabled: true}
	legacyChoice := model.Rule{ID: "customer-legacy", Source: "customer", SourceType: "user", MatchType: "domain_suffix", MatchValue: "legacy.example", Action: "DIRECT", Priority: 100, Enabled: true}
	withChoice := engine.Explain(ProfileGFW, []model.Rule{baseline, legacyBaseline, choice, legacyChoice}, Query{Domain: "a.example.org"})
	if withChoice.Matched == nil || withChoice.Matched.RuleID != choice.ID {
		t.Fatalf("customer choice lost to baseline: %#v", withChoice)
	}
	compiled := engine.Compile(ProfileGFW, []model.Rule{baseline, choice})
	customerIndex, adminIndex := -1, -1
	for i, rule := range compiled {
		if rule.RuleID == choice.ID {
			customerIndex = i
		}
		if rule.RuleID == baseline.ID {
			adminIndex = i
		}
	}
	if customerIndex < 0 || adminIndex < 0 || customerIndex >= adminIndex {
		t.Fatalf("dae compilation does not put customer choice before baseline: %#v", compiled)
	}
	protected := engine.Explain(ProfileGFW, []model.Rule{choice}, Query{Domain: "a.example.org", IsManagement: true})
	if protected.Matched == nil || protected.Matched.RuleID != "system-management" {
		t.Fatalf("customer choice overrode management rescue path: %#v", protected)
	}
	legacy := engine.Explain(ProfileGFW, []model.Rule{legacyBaseline, legacyChoice}, Query{Domain: "a.legacy.example"})
	if legacy.Matched == nil || legacy.Matched.RuleID != legacyChoice.ID {
		t.Fatalf("customer choice lost to legacy admin rule: %#v", legacy)
	}
	afterReset := engine.Explain(ProfileGFW, []model.Rule{baseline, legacyBaseline}, Query{Domain: "a.example.org"})
	if afterReset.Matched == nil || afterReset.Matched.RuleID != baseline.ID {
		t.Fatalf("support reset did not restore baseline: %#v", afterReset)
	}
}
