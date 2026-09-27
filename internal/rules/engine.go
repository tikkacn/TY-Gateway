package rules

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"tygateway/internal/model"
)

const (
	ProfileGFW         = "gfw_precise"
	ProfileBlackmatrix = "blackmatrix7"
)

var categories = []string{"China", "HK-Broker", "AI", "YouTube", "TikTok", "Netflix", "GitHub", "Google", "Microsoft", "Apple", "Telegram", "Final", "OpenAI", "Disney", "Steam", "Advertising", "Streaming", "Social", "Messaging", "Development", "Gaming"}

var visibleManagedCategories = []string{"China", "HK-Broker", "AI", "YouTube", "TikTok", "Netflix", "GitHub", "Google", "Microsoft", "Apple", "Telegram", "Final"}

func SupportedProfiles() []string   { return []string{ProfileGFW, ProfileBlackmatrix} }
func SupportedCategories() []string { return append([]string(nil), categories...) }
func IsVisibleManagedCategory(category string) bool {
	for _, visible := range visibleManagedCategories {
		if category == visible {
			return true
		}
	}
	return false
}

type Query struct {
	Domain       string
	IP           string
	SourceIP     string
	SourceMAC    string
	CountryCode  string
	IsLAN        bool
	IsManagement bool
}

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Explain(profile string, userRules []model.Rule, q Query) model.ExplainResult {
	profile = normalizeProfile(profile)
	candidates := e.candidates(profile, userRules, q)
	result := model.ExplainResult{Profile: profile, Candidates: candidates, Fallback: fallbackFor(profile)}
	if len(candidates) > 0 {
		result.Matched = &candidates[0]
	}
	return result
}

func (e *Engine) Compile(profile string, userRules []model.Rule) []model.CompiledRule {
	profile = normalizeProfile(profile)
	compiled := make([]model.CompiledRule, 0, len(userRules)+8)
	for _, r := range sortedRules(append(baseRules(profile), userRules...)) {
		if r.Enabled {
			compiled = append(compiled, toCompiled(r, "ordered policy"))
		}
	}
	return compiled
}

func (e *Engine) candidates(profile string, userRules []model.Rule, q Query) []model.CompiledRule {
	var matches []model.CompiledRule
	for _, r := range sortedRules(append(baseRules(profile), userRules...)) {
		if !r.Enabled || !scopeMatches(r, q) {
			continue
		}
		if matchRule(r, q) {
			why := "matched " + r.MatchType + " " + r.MatchValue
			if r.SourceType == "user" && r.Source == "customer" {
				why = "customer rule overrides the editable administrator baseline"
			} else if r.SourceType == "user" || r.SourceType == "admin" {
				why = "administrator baseline rule"
			}
			matches = append(matches, toCompiled(r, why))
		}
	}
	return matches
}

func baseRules(profile string) []model.Rule {
	base := []model.Rule{
		{ID: "system-management", Source: "system", SourceType: "system", MatchType: "management", MatchValue: "control-plane,frps,ota", Action: "DIRECT", Priority: 0, Enabled: true},
		{ID: "system-lan", Source: "system", SourceType: "system", MatchType: "lan", MatchValue: "private-ranges", Action: "DIRECT", Priority: 10, Enabled: true},
	}
	if profile == ProfileGFW {
		base = append(base,
			model.Rule{ID: "gfw-cn-domain", Source: "cn-domain", SourceType: "profile", MatchType: "domain_suffix", MatchValue: "baidu.com,qq.com,taobao.com,aliyun.com,bilibili.com,163.com", Action: "DIRECT", Priority: 200, Enabled: true},
			model.Rule{ID: "gfw-cn-ip", Source: "cn-geoip", SourceType: "profile", MatchType: "geoip", MatchValue: "CN", Action: "DIRECT", Priority: 400, Enabled: true},
			model.Rule{ID: "gfw-list", Source: "gfwlist", SourceType: "provider", Category: "GFW", MatchType: "domain_suffix", MatchValue: "google.com,youtube.com,openai.com,github.com,telegram.org,netflix.com", Action: "PROXY", Priority: 300, Enabled: true},
		)
	} else if profile == ProfileBlackmatrix {
		base = append(base,
			model.Rule{ID: "bm7-china", Source: "blackmatrix7", SourceType: "profile", Category: "China", MatchType: "domain_suffix", MatchValue: "baidu.com,qq.com,taobao.com,aliyun.com,bilibili.com,163.com", Action: "DIRECT", Priority: 200, Enabled: true},
		)
	}
	return base
}

func normalizeProfile(profile string) string {
	if strings.HasPrefix(profile, "managed_") {
		return profile
	}
	if profile != ProfileBlackmatrix {
		return ProfileGFW
	}
	return profile
}
func fallbackFor(profile string) string {
	return "DIRECT"
}

func sortedRules(in []model.Rule) []model.Rule {
	out := append([]model.Rule(nil), in...)
	sort.SliceStable(out, func(i, j int) bool {
		ti, tj := ruleTier(out[i]), ruleTier(out[j])
		if ti != tj {
			return ti < tj
		}
		pi, pj := effectivePriority(out[i]), effectivePriority(out[j])
		if pi != pj {
			return pi < pj
		}
		if out[i].Source == "customer" && out[j].Source == "customer" {
			if out[i].MatchType != out[j].MatchType {
				return out[i].MatchType == "domain"
			}
			if len(out[i].MatchValue) != len(out[j].MatchValue) {
				return len(out[i].MatchValue) > len(out[j].MatchValue)
			}
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func ruleTier(r model.Rule) int {
	if r.SourceType == "system" {
		return 0
	}
	if r.SourceType == "temporary" {
		return 1
	}
	// Customer choices override the administrator's editable baseline. Keep
	// immutable system routes above both; a support reset removes only this tier.
	if r.SourceType == "user" && r.Source == "customer" {
		return 2
	}
	if r.SourceType == "user" || r.SourceType == "admin" {
		return 3
	}
	// A service's domain rule must win over a broad China rule (including
	// domestic CDN addresses). This is independent of the UI card order.
	if r.Category == "China" || r.MatchType == "geoip" && strings.EqualFold(r.MatchValue, "CN") {
		return 5
	}
	if strings.HasPrefix(r.MatchType, "domain") {
		return 4
	}
	return 5
}

func effectivePriority(r model.Rule) int {
	// Lower priority number wins. Device-specific and user rules are overlays,
	// but the non-removable system protection rules remain above them.
	if r.SourceType == "system" {
		return r.Priority
	}
	if r.DeviceID != "" || r.SourceType == "user" || r.SourceType == "admin" {
		return 100 + r.Priority
	}
	return 200 + r.Priority
}

func scopeMatches(r model.Rule, q Query) bool {
	if r.SourceIP != "" && r.SourceIP != q.SourceIP {
		return false
	}
	if r.SourceMAC != "" && normalizeMAC(r.SourceMAC) != normalizeMAC(q.SourceMAC) {
		return false
	}
	return true
}

func matchRule(r model.Rule, q Query) bool {
	if r.MatchType == "all" {
		return true
	}
	if r.MatchType == "management" {
		return q.IsManagement
	}
	if r.MatchType == "lan" {
		return q.IsLAN || isPrivateIP(q.IP)
	}
	if r.MatchType == "category" {
		return false
	}
	values := splitValues(r.MatchValue)
	switch r.MatchType {
	case "all":
		return true
	case "domain_regex":
		ok, _ := regexp.MatchString(r.MatchValue, normalizeDomain(q.Domain))
		return ok
	case "domain", "domain_exact":
		for _, v := range values {
			if normalizeDomain(q.Domain) == normalizeDomain(v) {
				return true
			}
		}
	case "domain_suffix":
		for _, v := range values {
			if domainHasSuffix(q.Domain, v) {
				return true
			}
		}
	case "domain_keyword":
		for _, v := range values {
			if strings.Contains(normalizeDomain(q.Domain), normalizeDomain(v)) {
				return true
			}
		}
	case "ip", "cidr", "ip_cidr":
		for _, v := range values {
			if ipMatches(q.IP, v) {
				return true
			}
		}
	case "geoip":
		return strings.EqualFold(strings.TrimSpace(q.CountryCode), strings.TrimSpace(r.MatchValue))
	}
	return false
}

func toCompiled(r model.Rule, explanation string) model.CompiledRule {
	return model.CompiledRule{RuleID: r.ID, Source: r.Source, Match: r.MatchType + "(" + r.MatchValue + ")", Action: r.Action, Priority: r.Priority, Explanation: explanation}
}
func splitValues(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
func normalizeDomain(v string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".")
}
func domainHasSuffix(domain, suffix string) bool {
	d, s := normalizeDomain(domain), normalizeDomain(suffix)
	return d == s || strings.HasSuffix(d, "."+s)
}
func normalizeMAC(v string) string {
	return strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(v)))
}
func isPrivateIP(v string) bool {
	ip := net.ParseIP(strings.TrimSpace(v))
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
func ipMatches(ip, rule string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	if _, n, err := net.ParseCIDR(strings.TrimSpace(rule)); err == nil {
		return n.Contains(parsed)
	}
	return parsed.Equal(net.ParseIP(strings.TrimSpace(rule)))
}

func RenderDaeCandidate(profile string, compiled []model.CompiledRule) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# TY Gateway candidate; profile=%s; generated by compiler\n", normalizeProfile(profile))
	b.WriteString("# This is an artifact for review. OEC/dae integration is intentionally not enabled in MVP.\n")
	for _, r := range compiled {
		fmt.Fprintf(&b, "# %03d %s %s -> %s\n", r.Priority, r.Match, r.Source, r.Action)
	}
	if normalizeProfile(profile) == ProfileGFW {
		b.WriteString("fallback: direct\n")
	} else {
		b.WriteString("fallback: auto\n")
	}
	return b.String()
}
