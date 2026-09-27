package rules

import (
	"strings"
	"testing"

	"tygateway/internal/model"
)

func TestRenderDaeManagedKeepsProxyOffByDefault(t *testing.T) {
	rendered, err := RenderDaeManaged(model.DaePolicy{Profile: ProfileGFW, SubscriptionPresent: true, Rules: []model.CompiledRule{
		{RuleID: "system-lan", Match: "lan(private-ranges)", Action: "DIRECT"},
		{RuleID: "user-proxy", Match: "domain_suffix(example.com)", Action: "NODE:node-1"},
		{RuleID: "user-block", Match: "domain(bad.example)", Action: "BLOCK"},
	}, Nodes: []model.Node{{ID: "node-1", Name: "HK premium"}}, DirectHosts: []string{"oec.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "# proxy_enabled: false") || !strings.Contains(rendered, "fallback: direct") {
		t.Fatalf("disabled policy does not fail closed: %s", rendered)
	}
	if strings.Contains(rendered, "ty_gateway_proxy {") || strings.Contains(rendered, "NODE:node-1") {
		t.Fatalf("disabled policy emitted a proxy group: %s", rendered)
	}
	if !strings.Contains(rendered, "domain(suffix: 'example.com') -> direct") || !strings.Contains(rendered, "domain(full: 'bad.example') -> block") {
		t.Fatalf("disabled policy did not preserve direct/block semantics: %s", rendered)
	}
	if !strings.Contains(rendered, "domain(full: 'oec.example.test') -> direct") {
		t.Fatalf("management exception is missing: %s", rendered)
	}
}

func TestRenderDaeManagedEnablesSelectiveRulesAndNodeGroup(t *testing.T) {
	rendered, err := RenderDaeManaged(model.DaePolicy{Profile: ProfileBlackmatrix, ProxyEnabled: true, Interface: "eth0", DNSBind: "10.23.42.10", SubscriptionPresent: true, Rules: []model.CompiledRule{
		{RuleID: "openai", Source: "OpenAI", Match: "domain_suffix(openai.com)", Action: "NODE:node-1"},
		{RuleID: "cn-ip", Match: "geoip(CN)", Action: "DIRECT"},
	}, Nodes: []model.Node{{ID: "node-1", Name: "Tokyo '01'", Group: "Japan"}}, DirectHosts: []string{"203.0.113.166", "oec.example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "# proxy_enabled: true") || !strings.Contains(rendered, "fallback: ty_gateway_proxy") || !strings.Contains(rendered, "lan_interface: eth0") || !strings.Contains(rendered, "wan_interface: auto") || !strings.Contains(rendered, "dial_mode: domain") || strings.Contains(rendered, "dial_mode: domain++") || strings.Contains(rendered, "sniffing_timeout:") {
		t.Fatalf("enabled profile policy does not use the documented proxy fallback: %s", rendered)
	}
	if !strings.Contains(rendered, "dns {\n  ipversion_prefer: 4\n  bind: '10.23.42.10:5353'") {
		t.Fatalf("enabled profile did not force IPv4 DNS answers or bind the local DNS listener: %s", rendered)
	}
	if !strings.Contains(rendered, "googledns: 'https://dns.google/dns-query'") ||
		!strings.Contains(rendered, "domain(suffix: 'dns.google') -> ty_gateway_proxy") ||
		!strings.Contains(rendered, "upstream(googledns) -> accept") ||
		!strings.Contains(rendered, "domain(geosite:cn) -> direct") {
		t.Fatalf("enabled profile did not protect non-CN DNS through the proxy: %s", rendered)
	}
	if !strings.Contains(rendered, `filter: name('Tokyo \'01\'')`) {
		t.Fatalf("selected-node filter missing or not escaped: %s", rendered)
	}
	if !strings.Contains(rendered, "domain(suffix: 'openai.com') -> ty_gateway_node_") {
		t.Fatalf("selected node is not used by its domain rule: %s", rendered)
	}
	if !strings.Contains(rendered, "dip('203.0.113.166') -> direct") || !strings.Contains(rendered, "domain(full: 'oec.example.test') -> direct") {
		t.Fatalf("management traffic is not pinned direct: %s", rendered)
	}
	if strings.Contains(rendered, "subscription?token=") || strings.Contains(rendered, "password=") || strings.Contains(rendered, "token=") {
		t.Fatalf("renderer leaked a subscription secret: %s", rendered)
	}
}

func TestRenderDaeManagedRejectsUnsafeRulesAndUnknownNodes(t *testing.T) {
	cases := []model.CompiledRule{
		{RuleID: "injection", Match: "domain(full:example.com)\n fallback: ty_gateway_auto", Action: "PROXY"},
		{RuleID: "unsupported", Match: "category(OpenAI)", Action: "PROXY"},
		{RuleID: "missing-node", Match: "domain_suffix(example.com)", Action: "NODE:missing"},
	}
	for _, rule := range cases {
		if _, err := RenderDaeManaged(model.DaePolicy{Profile: ProfileGFW, ProxyEnabled: true, SubscriptionPresent: true, Rules: []model.CompiledRule{rule}}); err == nil {
			t.Errorf("accepted unsafe or unresolved rule: %#v", rule)
		}
	}
	if _, err := RenderDaeManaged(model.DaePolicy{Profile: ProfileGFW, ProxyEnabled: true, SubscriptionPresent: true, Interface: "eth0\n  auto_config_kernel_parameter: true"}); err == nil {
		t.Fatal("accepted an unsafe interface name")
	}
}

func TestRenderDaeRegionAutoAndOrderedFailover(t *testing.T) {
	nodes := []model.Node{{ID: "a", Name: "ALI-HK(香港1)"}, {ID: "b", Name: "GCC-HK(香港2)"}, {ID: "c", Name: "ORC-US(美国4)"}}
	config, err := RenderDaeManaged(model.DaePolicy{Profile: "managed_geo", ProxyEnabled: true, SubscriptionPresent: true, Interface: "eth0", Nodes: nodes, Rules: []model.CompiledRule{
		{RuleID: "broker", Match: "domain_suffix(broker.example)", Action: "REGION:HK"},
		{RuleID: "ai", Match: "domain_suffix(ai.example)", Action: "FAILOVER:a,c"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "filter: name('ALI-HK(香港1)')\n    filter: name('GCC-HK(香港2)')\n    policy: min_moving_avg") && !strings.Contains(config, "filter: name('GCC-HK(香港2)')\n    filter: name('ALI-HK(香港1)')\n    policy: min_moving_avg") {
		t.Fatalf("region group is not limited to Hong Kong nodes: %s", config)
	}
	if !strings.Contains(config, "filter: name('ALI-HK(香港1)')\n    filter: name('ORC-US(美国4)') [add_latency: 5000ms]\n    policy: min_moving_avg") {
		t.Fatalf("health-based primary/backup order missing: %s", config)
	}
	if strings.Contains(config, "filter: name('ORC-US(美国4)')\n    filter: name('GCC-HK(香港2)')") {
		t.Fatal("region group included a non-region node")
	}
}

func TestRenderDaeSystemDirectRoutesPrecedeCustomerOverrides(t *testing.T) {
	config, err := RenderDaeManaged(model.DaePolicy{Profile: "managed_geo", ProxyEnabled: true, SubscriptionPresent: true, Interface: "eth0", DirectHosts: []string{"control.example.test", "192.0.2.5"}, Rules: []model.CompiledRule{
		{RuleID: "customer-control", Match: "domain(control.example.test)", Action: "PROXY"},
		{RuleID: "customer-lan", Match: "cidr(10.23.0.0/16)", Action: "PROXY"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, pinned := range []string{
		"domain(full: 'control.example.test') -> direct",
		"dip('192.0.2.5') -> direct",
		"dip(geoip:private, 224.0.0.0/3, 'ff00::/8') -> direct",
	} {
		if !strings.Contains(config, pinned) || strings.Index(config, pinned) > strings.Index(config, "domain(full: 'control.example.test') -> ty_gateway_proxy") {
			t.Fatalf("immutable system route lost ordering: %s", config)
		}
	}
}

func TestRenderDaeIPAndCIDRCustomerRules(t *testing.T) {
	config, err := RenderDaeManaged(model.DaePolicy{Profile: "managed_geo", ProxyEnabled: true, SubscriptionPresent: true, Interface: "eth0", Rules: []model.CompiledRule{
		{RuleID: "ipv4", Match: "cidr(192.0.2.0/24)", Action: "DIRECT"},
		{RuleID: "ipv6", Match: "ip(2001:db8::1)", Action: "BLOCK"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(config, "dip('192.0.2.0/24') -> direct") || !strings.Contains(config, "dip('2001:db8::1') -> block") {
		t.Fatalf("IP/CIDR rules not rendered as dae destination-IP predicates: %s", config)
	}
}
