package ruleseed

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"tygateway/internal/model"
)

func TestSeedsAreCompletePublicAndValidated(t *testing.T) {
	if len(Versions()) != 4 || len(Catalog()) != 4 {
		t.Fatal("release is missing a public seed")
	}
	for _, id := range Profiles {
		p, ok := Get(id)
		if !ok || Validate(p) != nil {
			t.Fatalf("invalid %s seed", id)
		}
		seen := make(map[string]bool)
		for _, r := range p.Rules {
			seen[r.Category] = true
		}
		for _, c := range []string{"AI", "YouTube", "HK-Broker", "China", "Final"} {
			if !seen[c] {
				t.Fatalf("%s is missing %s", id, c)
			}
		}
		private := p
		private.Rules = append([]model.CompiledRule(nil), p.Rules...)
		private.Rules[0].SourceType = "user"
		if Validate(private) == nil {
			t.Fatal("private rule was accepted into public seed")
		}
	}
}

func TestCompactHydratePreservesEveryActionOrderAndDefault(t *testing.T) {
	p, _ := Get("managed_meta")
	provider := append([]model.CompiledRule(nil), p.Rules...)
	for i := range provider {
		provider[i].DefaultAction = provider[i].Action
		if provider[i].Category == "AI" {
			provider[i].Action = "NODE:customer-node"
		}
	}
	personal := model.CompiledRule{RuleID: "personal", Source: "customer", SourceType: "user", Match: "domain(example.com)", Action: "DIRECT", Priority: 1}
	full := model.DeviceConfig{Profile: p.Profile, RulePackageVersion: p.Version, Rules: append([]model.CompiledRule{personal}, provider...), BaseRules: append([]model.CompiledRule{personal}, provider...), Preferences: map[string]string{"AI": "customer-node"}}
	before, _ := json.Marshal(full)
	compact := Compact(full, Versions())
	if compact.RuleSeedVersion != p.Version || compact.Rules[0].Match != personal.Match || compact.Rules[1].Match != "" {
		t.Fatal("unexpected rule omission")
	}
	if full.Rules[1].Match == "" {
		t.Fatal("compaction mutated original rules")
	}
	small, _ := json.Marshal(compact)
	t.Logf("Rule data before=%d bytes, seed reference=%d bytes", len(before), len(small))
	if len(small) >= len(before)/5 {
		t.Fatalf("seed reference did not materially reduce payload: %d vs %d", len(small), len(before))
	}
	restored, err := Hydrate(compact)
	if err != nil || !reflect.DeepEqual(restored, full) {
		t.Fatal("rule order/action/default changed after seed hydration", err)
	}
	for _, advertised := range []map[string]string{nil, {p.Profile: strings.Repeat("0", 64)}} {
		if !reflect.DeepEqual(Compact(full, advertised), full) {
			t.Fatal("old/different client did not receive full rules")
		}
	}
	bad := Compact(full, Versions())
	bad.RuleSeedVersion = strings.Repeat("0", 64)
	if _, err := Hydrate(bad); err == nil {
		t.Fatal("wrong seed version was accepted")
	}
	bad = Compact(full, Versions())
	bad.Rules[1].RuleID = "missing-seed-rule"
	if _, err := Hydrate(bad); err == nil {
		t.Fatal("missing rule reference was accepted")
	}
	bad = Compact(full, Versions())
	bad.Rules[1].Category = "wrong-category"
	if _, err := Hydrate(bad); err == nil {
		t.Fatal("different category was accepted")
	}
}
