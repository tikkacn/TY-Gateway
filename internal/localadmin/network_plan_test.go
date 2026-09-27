package localadmin

import (
	"strings"
	"testing"
)

func validPlan() NetworkPlanInput {
	return NetworkPlanInput{
		AddressCIDR: "10.23.42.211/24",
		Gateway:     "10.23.42.1",
		DHCPEnabled: true,
		PoolStart:   "10.23.42.100",
		PoolEnd:     "10.23.42.200",
		DNSMode:     "router",
	}
}

func TestPreviewNetworkPlanIsValidationOnly(t *testing.T) {
	preview, err := PreviewNetworkPlan(validPlan())
	if err != nil {
		t.Fatal(err)
	}
	if !preview.Valid || preview.ApplyEnabled {
		t.Fatalf("preview must be valid but never applicable: %+v", preview)
	}
	if preview.AddressCIDR != "10.23.42.211/24" || preview.Gateway != "10.23.42.1" {
		t.Fatalf("unexpected normalized addresses: %+v", preview)
	}
	if preview.ClientGateway != "10.23.42.211" {
		t.Fatalf("DHCP must advertise the OEC address as the client gateway: %+v", preview)
	}
	if !strings.Contains(strings.Join(preview.Warnings, " "), "不会更改") {
		t.Fatalf("preview must explicitly disclose no changes: %+v", preview.Warnings)
	}
	if !strings.Contains(preview.DNSDescription, "主路由") {
		t.Fatalf("router DNS semantics should be explicit: %q", preview.DNSDescription)
	}
}

func TestBypassRouterUsesOECAsClientGatewayAndRouterAsUpstream(t *testing.T) {
	plan := validPlan()
	plan.AddressCIDR = "10.23.42.10/24"
	preview, err := PreviewNetworkPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if preview.ClientGateway != "10.23.42.10" || preview.Gateway != "10.23.42.1" {
		t.Fatalf("client and upstream gateways were not distinguished: %+v", preview)
	}
}

func TestPreviewNetworkPlanRejectsUnsafeRanges(t *testing.T) {
	tests := []struct {
		name   string
		change func(*NetworkPlanInput)
	}{
		{name: "pool contains device", change: func(p *NetworkPlanInput) { p.PoolEnd = "10.23.42.220" }},
		{name: "pool contains router", change: func(p *NetworkPlanInput) { p.PoolStart = "10.23.42.1" }},
		{name: "network address", change: func(p *NetworkPlanInput) { p.AddressCIDR = "10.23.42.0/24" }},
		{name: "gateway outside subnet", change: func(p *NetworkPlanInput) { p.Gateway = "10.23.43.1" }},
		{name: "large pool", change: func(p *NetworkPlanInput) {
			p.AddressCIDR, p.Gateway = "10.0.0.2/8", "10.0.0.1"
			p.PoolStart, p.PoolEnd = "10.0.1.0", "10.0.20.0"
		}},
		{name: "unknown dns mode", change: func(p *NetworkPlanInput) { p.DNSMode = "automatic" }},
		{name: "broadcast dns", change: func(p *NetworkPlanInput) {
			p.DNSMode, p.DNSServers = "custom", []string{"255.255.255.255"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := validPlan()
			test.change(&plan)
			if _, err := PreviewNetworkPlan(plan); err == nil {
				t.Fatal("expected invalid network plan to be rejected")
			}
		})
	}
}

func TestPreviewNetworkPlanAllowsDisabledDHCPAndCustomDNS(t *testing.T) {
	plan := validPlan()
	plan.DHCPEnabled = false
	plan.PoolStart, plan.PoolEnd = "", ""
	plan.DNSMode = "custom"
	plan.DNSServers = []string{"1.1.1.1", "8.8.8.8"}
	preview, err := PreviewNetworkPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	if preview.DHCPEnabled || preview.ClientGateway != "" || len(preview.DNSServers) != 2 || preview.ApplyEnabled {
		t.Fatalf("unexpected preview: %+v", preview)
	}
}

func TestPreviewNetworkPlanRejectsDuplicateCustomDNS(t *testing.T) {
	plan := validPlan()
	plan.DNSMode = "custom"
	plan.DNSServers = []string{"1.1.1.1", "1.1.1.1"}
	if _, err := PreviewNetworkPlan(plan); err == nil {
		t.Fatal("expected duplicate DNS addresses to be rejected")
	}
}
