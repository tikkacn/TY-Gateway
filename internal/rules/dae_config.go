package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"tygateway/internal/model"
	"tygateway/internal/selection"
)

// RenderDaeManaged renders only the TY Gateway include. It never renders a
// subscription URL or node credentials; dae reads those from its own staged
// subscription file. Input strings are parsed and allow-listed before they can
// enter the privileged helper's configuration.
func RenderDaeManaged(policy model.DaePolicy) (string, error) {
	profile := normalizeProfile(policy.Profile)
	if policy.ProxyEnabled && !policy.SubscriptionPresent {
		return "", errors.New("proxy requires a bound subscription")
	}
	if policy.ProxyEnabled && !validInterfaceName(policy.Interface) {
		return "", errors.New("proxy requires a valid network interface")
	}
	nodeByID := make(map[string]model.Node, len(policy.Nodes))
	for _, node := range policy.Nodes {
		if node.ID != "" {
			nodeByID[node.ID] = node
		}
	}

	targets := map[string]string{"PROXY": "ty_gateway_proxy", "AUTO": "ty_gateway_auto"}
	groupAliases := make(map[string]string)
	groupFilters := make(map[string]string)
	groupPolicies := make(map[string]string)
	var routes []string
	for _, host := range policy.DirectHosts {
		rule, err := directHostRule(host)
		if err != nil {
			return "", err
		}
		if rule != "" {
			routes = append(routes, rule)
		}
	}
	// Always keep private, multicast, and link-local destinations on the LAN.
	routes = append(routes, "dip(geoip:private, 224.0.0.0/3, 'ff00::/8') -> direct")

	fallback := "direct"
	if policy.ProxyEnabled {
		// The official dae side-router guidance is to make the safe exceptions
		// explicit and send otherwise-unmatched traffic to the proxy group. A
		// direct fallback is not reliable for domain rules: domain++ cannot
		// re-route a connection that the kernel already classified as direct.
		fallback = "ty_gateway_proxy"
		// The DNS upstream is DoH, so its hostname must itself be routed via
		// the proxy. Keep this before policy rules so a user rule cannot make
		// dae's external resolver silently go direct.
		routes = append(routes, "domain(suffix: 'dns.google') -> ty_gateway_proxy")
	}
	for _, rule := range policy.Rules {
		matchType, values, ok := splitCompiledMatch(rule.Match)
		if !ok {
			return "", fmt.Errorf("unsupported compiled rule %q", rule.RuleID)
		}
		if matchType == "management" || matchType == "lan" {
			continue // covered by the immutable rules above
		}
		if matchType == "all" {
			target, err := daeTarget(rule.Action, policy.ProxyEnabled, nodeByID, targets, groupAliases, groupFilters, groupPolicies)
			if err != nil {
				return "", err
			}
			fallback = target
			continue
		}
		condition, err := daeCondition(matchType, values)
		if err != nil {
			return "", fmt.Errorf("rule %q: %w", rule.RuleID, err)
		}
		target, err := daeTarget(rule.Action, policy.ProxyEnabled, nodeByID, targets, groupAliases, groupFilters, groupPolicies)
		if err != nil {
			return "", fmt.Errorf("rule %q: %w", rule.RuleID, err)
		}
		routes = append(routes, condition+" -> "+target)
	}

	var b strings.Builder
	if policy.RulePackageVersion != "" {
		if len(policy.RulePackageVersion) != 64 {
			return "", errors.New("invalid rule version")
		}
		if _, err := hex.DecodeString(policy.RulePackageVersion); err != nil {
			return "", errors.New("invalid rule version")
		}
		fmt.Fprintf(&b, "# rule_package_version: %s\n", policy.RulePackageVersion)
	}
	fmt.Fprintf(&b, "# Managed by TY Gateway. Do not edit.\n# profile: %s\n# proxy_enabled: %t\n", profile, policy.ProxyEnabled)
	if policy.ProxyEnabled {
		// OEC is a one-port bypass gateway. Both sides intentionally use the
		// same physical NIC; this block is emitted only after the local safety
		// gate permits proxy routing. Use dae's documented default dial mode;
		// domain++ cannot rescue traffic already classified as direct.
		fmt.Fprintf(&b, "global {\n  lan_interface: %s\n  wan_interface: auto\n  dial_mode: domain\n}\n", policy.Interface)
	}
	if policy.SubscriptionPresent {
		b.WriteString("subscription {\n  ty_gateway: 'file://ty-gateway/subscription.raw'\n}\n")
	}
	if policy.ProxyEnabled {
		// Prefer IPv4 answers in dae's DNS path. Subscription family selection
		// itself follows the operator's explicit "IPv6" node-name convention.
		b.WriteString("dns {\n  ipversion_prefer: 4\n")
		if policy.DNSBind != "" {
			if address, err := netip.ParseAddr(policy.DNSBind); err != nil || !address.Is4() || address.IsUnspecified() || address.IsLoopback() {
				return "", errors.New("invalid IPv4 DNS bind address")
			} else {
				fmt.Fprintf(&b, "  bind: '%s:5353'\n", address.String())
			}
			if strings.HasPrefix(profile, "managed_") {
				// Managed packages must not consult an unrelated on-device geosite database.
				b.WriteString("  upstream {\n    googledns: 'https://dns.google/dns-query'\n  }\n  routing {\n    request {\n      fallback: googledns\n    }\n    response {\n      fallback: accept\n    }\n  }\n")
			} else {
				b.WriteString("  upstream {\n    googledns: 'https://dns.google/dns-query'\n    alidns: 'udp://dns.alidns.com:53'\n  }\n  routing {\n    request {\n      qname(geosite:cn) -> alidns\n      fallback: googledns\n    }\n    response {\n      upstream(googledns) -> accept\n      ip(geoip:private) && !qname(geosite:cn) -> googledns\n      fallback: accept\n    }\n  }\n")
			}
		}
		b.WriteString("}\n")
	}
	if policy.ProxyEnabled {
		b.WriteString("group {\n")
		b.WriteString("  ty_gateway_proxy {\n    filter: subtag(ty_gateway)\n    policy: min_moving_avg\n  }\n")
		b.WriteString("  ty_gateway_auto {\n    filter: subtag(ty_gateway)\n    policy: min_moving_avg\n  }\n")
		groupNames := make([]string, 0, len(groupFilters))
		for name := range groupFilters {
			groupNames = append(groupNames, name)
		}
		sort.Strings(groupNames)
		for _, name := range groupNames {
			filter := groupFilters[name]
			policyName := groupPolicies[name]
			if policyName == "" {
				policyName = "fixed(0)"
			}
			fmt.Fprintf(&b, "  %s {\n    filter: %s\n    policy: %s\n  }\n", name, filter, policyName)
		}
		b.WriteString("}\n")
	}
	b.WriteString("routing {\n")
	for _, route := range routes {
		b.WriteString("  ")
		b.WriteString(route)
		b.WriteByte('\n')
	}
	if policy.ProxyEnabled && !strings.HasPrefix(profile, "managed_") {
		// Keep the complete China domain set as a late direct exception. Late
		// placement preserves explicit user/provider proxy rules above it.
		b.WriteString("  domain(geosite:cn) -> direct\n")
	}
	fmt.Fprintf(&b, "  fallback: %s\n}\n", fallback)
	return b.String(), nil
}

func daeTarget(action string, enabled bool, nodes map[string]model.Node, targets, aliases, groups, policies map[string]string) (string, error) {
	rawAction := strings.TrimSpace(action)
	action = strings.ToUpper(rawAction)
	if !enabled && action != "BLOCK" {
		return "direct", nil
	}
	switch action {
	case "DIRECT":
		return "direct", nil
	case "BLOCK":
		return "block", nil
	case "PROXY", "AUTO":
		if !enabled {
			return "direct", nil
		}
		return targets[action], nil
	}
	if strings.HasPrefix(action, "NODE:") {
		id := strings.TrimSpace(rawAction[len("NODE:"):])
		node, ok := nodes[id]
		if !ok || strings.TrimSpace(node.Name) == "" {
			return "", errors.New("selected node is unavailable")
		}
		name, exists := aliases["NODE:"+id]
		if !exists {
			name = stableGroupName("node", id)
			filter, err := exactNodeFilter(node.Name)
			if err != nil {
				return "", err
			}
			groups[name] = filter
			aliases["NODE:"+id] = name
		}
		return name, nil
	}
	if strings.HasPrefix(action, "REGION:") {
		code := strings.TrimSpace(rawAction[len("REGION:"):])
		if selection.RegionName(code) == "" {
			return "", errors.New("invalid region selection")
		}
		key := "REGION:" + code
		if name, exists := aliases[key]; exists {
			return name, nil
		}
		filters := []string{}
		for _, node := range nodes {
			if selection.RegionForName(node.Name) == code {
				filter, err := exactNodeFilter(node.Name)
				if err != nil {
					return "", err
				}
				filters = append(filters, filter)
			}
		}
		if len(filters) == 0 {
			return "", errors.New("selected region has no validated nodes")
		}
		name := stableGroupName("region", code)
		groups[name] = strings.Join(filters, "\n    filter: ")
		policies[name] = "min_moving_avg"
		aliases[key] = name
		return name, nil
	}
	if strings.HasPrefix(action, "FAILOVER:") {
		choice, ok := selection.Parse("@failover:" + strings.TrimSpace(rawAction[len("FAILOVER:"):]))
		if !ok || choice.Kind != "failover" {
			return "", errors.New("invalid failover selection")
		}
		key := "FAILOVER:" + strings.Join(choice.Nodes, ",")
		if name, exists := aliases[key]; exists {
			return name, nil
		}
		filters := make([]string, 0, len(choice.Nodes))
		for i, id := range choice.Nodes {
			node, found := nodes[id]
			if !found {
				return "", errors.New("failover node is unavailable")
			}
			filter, err := exactNodeFilter(node.Name)
			if err != nil {
				return "", err
			}
			if i > 0 {
				filter += fmt.Sprintf(" [add_latency: %dms]", i*5000)
			}
			filters = append(filters, filter)
		}
		name := stableGroupName("failover", key)
		groups[name] = strings.Join(filters, "\n    filter: ")
		policies[name] = "min_moving_avg"
		aliases[key] = name
		return name, nil
	}
	if strings.HasPrefix(action, "GROUP:") {
		group := strings.TrimSpace(rawAction[len("GROUP:"):])
		if group == "" {
			return "", errors.New("selected node group is unavailable")
		}
		name, exists := aliases["GROUP:"+group]
		if !exists {
			var filters []string
			for _, node := range nodes {
				if node.Group == group {
					filter, err := exactNodeFilter(node.Name)
					if err != nil {
						return "", err
					}
					filters = append(filters, filter)
				}
			}
			if len(filters) == 0 {
				return "", errors.New("selected node group is unavailable")
			}
			name = stableGroupName("group", group)
			groups[name] = strings.Join(filters, "\n    filter: ")
			aliases["GROUP:"+group] = name
		}
		return name, nil
	}
	return "", errors.New("unsupported policy action")
}

func daeCondition(matchType string, values []string) (string, error) {
	if len(values) == 0 {
		return "", errors.New("empty match value")
	}
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return "", errors.New("invalid match value")
		}
		quoted = append(quoted, daeQuote(value))
	}
	switch matchType {
	case "domain_regex":
		if len(values) != 1 {
			return "", errors.New("invalid regex rule")
		}
		if _, err := regexp.Compile(values[0]); err != nil {
			return "", err
		}
		return "domain(regex: " + quoted[0] + ")", nil
	case "domain", "domain_exact":
		for i := range quoted {
			quoted[i] = "full: " + quoted[i]
		}
		return "domain(" + strings.Join(quoted, ", ") + ")", nil
	case "domain_suffix":
		for i := range quoted {
			quoted[i] = "suffix: " + quoted[i]
		}
		return "domain(" + strings.Join(quoted, ", ") + ")", nil
	case "domain_keyword":
		for i := range quoted {
			quoted[i] = "keyword: " + quoted[i]
		}
		return "domain(" + strings.Join(quoted, ", ") + ")", nil
	case "ip", "cidr", "ip_cidr":
		for _, value := range values {
			if _, err := netip.ParsePrefix(strings.TrimSpace(value)); err != nil {
				if _, ipErr := netip.ParseAddr(strings.TrimSpace(value)); ipErr != nil {
					return "", errors.New("invalid IP match value")
				}
			}
		}
		return "dip(" + strings.Join(quoted, ", ") + ")", nil
	case "geoip":
		if len(values) != 1 || !isCountryCode(values[0]) {
			return "", errors.New("invalid GeoIP match value")
		}
		return "dip(geoip:" + strings.ToLower(strings.TrimSpace(values[0])) + ")", nil
	default:
		return "", errors.New("unsupported match type")
	}
}

func splitCompiledMatch(value string) (string, []string, bool) {
	open := strings.IndexByte(value, '(')
	if open <= 0 || !strings.HasSuffix(value, ")") {
		return "", nil, false
	}
	kind := strings.TrimSpace(value[:open])
	inside := strings.TrimSpace(value[open+1 : len(value)-1])
	if kind == "domain_regex" {
		return kind, []string{inside}, inside != ""
	}
	if kind == "all" {
		return kind, nil, true
	}
	return kind, strings.Split(inside, ","), inside != ""
}

func directHostRule(host string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", nil
	}
	if strings.ContainsAny(host, "\r\n/:@ ") {
		return "", errors.New("invalid direct management host")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return "dip(" + daeQuote(address.String()) + ") -> direct", nil
	}
	if !validDomain(host) {
		return "", errors.New("invalid direct management host")
	}
	return "domain(full: " + daeQuote(strings.ToLower(host)) + ") -> direct", nil
}

func exactNodeFilter(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, "\r\n") {
		return "", errors.New("invalid node name")
	}
	// dae's name() filter uses an unkeyed argument for an exact node-name
	// match. The `full:` key is valid for domain(), but is rejected by dae in
	// group filters and makes the whole staged reload fail.
	return "name(" + daeQuote(name) + ")", nil
}

func stableGroupName(kind, value string) string {
	hash := sha256.Sum256([]byte(value))
	return "ty_gateway_" + kind + "_" + hex.EncodeToString(hash[:6])
}

func daeQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `\'`)
	return "'" + value + "'"
}

func validDomain(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || strings.ContainsAny(value, "/:@ ") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r >= 0x80) {
				return false
			}
		}
	}
	return true
}

func isCountryCode(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
}

func validInterfaceName(value string) bool {
	if len(value) == 0 || len(value) > 15 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}
