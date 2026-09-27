package rules

import (
	"strings"
	"testing"
	"tygateway/internal/model"
)

func TestManagedPolicyDoesNotMixLegacyRules(t *testing.T) {
	p := []model.Rule{{ID: "ai", SourceType: "provider", Category: "AI", MatchType: "domain_suffix", MatchValue: "openai.com", Action: "PROXY", Enabled: true}, {ID: "end", SourceType: "provider", MatchType: "all", Action: "DIRECT", Priority: 9999, Enabled: true}}
	p = ApplyNodePreferences(Policy(model.Device{Profile: "managed_gfw"}, p, nil, nil, false), map[string]string{"AI": "@direct"}, nil)
	found := New().ExplainPolicy("managed_gfw", p, Query{Domain: "openai.com"})
	if found.Matched == nil || found.Matched.Action != "DIRECT" {
		t.Fatal("direct choice lost")
	}
	output, err := RenderDaeManaged(model.DaePolicy{Profile: "managed_gfw", Interface: "eth0", DNSBind: "10.23.42.10", ProxyEnabled: true, SubscriptionPresent: true, Rules: New().CompilePolicy(p)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "geosite:cn") || strings.Contains(output, "baidu.com") {
		t.Fatal("legacy policy leaked")
	}
	if !strings.Contains(output, "fallback: direct") {
		t.Fatal("GFW fallback lost")
	}
}
func TestPreferenceKeepsBlockAndRegexCommas(t *testing.T) {
	r := model.Rule{Category: "AI", Action: "BLOCK"}
	applyNodePreference(&r, map[string]string{"AI": "@direct"}, nil)
	if r.Action != "BLOCK" {
		t.Fatal("block overridden")
	}
	kind, values, ok := splitCompiledMatch(`domain_regex(^a{1,3}\.example\.com$)`)
	if !ok || len(values) != 1 {
		t.Fatal("regex split on comma")
	}
	if _, err := daeCondition(kind, values); err != nil {
		t.Fatal(err)
	}
}
