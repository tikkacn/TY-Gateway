package selection

import (
	"testing"

	"tygateway/internal/model"
)

func TestRegionDetectionAndPreferenceValidation(t *testing.T) {
	nodes := []model.Node{{ID: "a", Name: "ALI-HK(香港1)"}, {ID: "b", Name: "ORC-US(美国4)"}, {ID: "c", Name: "ALI-SGP(新加坡4)"}}
	for name, want := range map[string]string{"ALI-HK(香港1)": "HK", "ORC-US(美国4)": "US", "ALI-SGP(新加坡4)": "SG", "AUS-other": ""} {
		if got := RegionForName(name); got != want {
			t.Errorf("%q: got region %q, want %q", name, got, want)
		}
	}
	for _, value := range []string{"", "@direct", "@proxy", "@region:HK", "a", "@failover:a,b", "@failover:a,b,c"} {
		if !Valid(value, nodes) {
			t.Errorf("valid choice rejected: %q", value)
		}
	}
	for _, value := range []string{"@region:DE", "@region:INVALID", "missing", "@failover:a,a", "@failover:a,missing", "@failover:a,b,c,a", "@failover:a\n,b"} {
		if Valid(value, nodes) {
			t.Errorf("invalid choice accepted: %q", value)
		}
	}
	if Action("@region:HK") != "REGION:HK" || Action("@failover:a,b") != "FAILOVER:a,b" {
		t.Fatal("preference action did not preserve routing semantics")
	}
}
