package providers

import "testing"

func TestParseClashRules(t *testing.T) {
	r, err := ParseClashRules("Blackmatrix7", "DOMAIN-SUFFIX,example.com,US\nIP-CIDR,1.2.3.0/24,DIRECT\n# comment\n")
	if err != nil || len(r) != 2 {
		t.Fatalf("%d %v", len(r), err)
	}
	if r[0].Action != "US" || r[1].MatchType != "cidr" {
		t.Fatalf("unexpected rules: %#v", r)
	}
}
