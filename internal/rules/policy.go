package rules

import (
	"strings"
	"time"
	"tygateway/internal/model"
	"tygateway/internal/selection"
)

// Policy materializes category selection and a bounded temporary override.
// The ordinary engine then applies identical ordering to compile and explain.
func Policy(d model.Device, input []model.Rule, prefs map[string]string, nodes []model.Node, temporary bool) []model.Rule {
	valid := map[string]bool{}
	for _, n := range nodes {
		valid["NODE:"+n.ID] = true
		if n.Group != "" {
			valid["GROUP:"+n.Group] = true
		}
	}
	out := append(baseRules(normalizeProfile(d.Profile)), input...)
	proxyEnabled := temporary && d.CustomerOverrideAction == "PROXY" && d.CustomerOverrideUntil != nil && d.CustomerOverrideUntil.After(time.Now().UTC())
	forceDirect := temporary && !proxyEnabled
	for i := range out {
		r := &out[i]
		if proxyEnabled && r.SourceType != "system" && r.SourceType != "user" && r.SourceType != "admin" {
			applyNodePreference(r, prefs, nodes)
		}
		// The temporary customer switch gates all proxy-capable policy. With no
		// active switch, the device remains DIRECT; explicit BLOCK rules continue
		// to work, while system protection rules are never rewritten.
		if forceDirect && r.SourceType != "system" && r.Action != "BLOCK" {
			r.Action = "DIRECT"
		}
		if (strings.HasPrefix(r.Action, "NODE:") || strings.HasPrefix(r.Action, "GROUP:")) && !valid[r.Action] {
			r.Action = "AUTO"
		}
	}
	return out
}

// ApplyNodePreferences applies the customer-selected node to category-owned
// rules without enabling or disabling proxy routing. The local OEC agent uses
// the non-temporary BaseRules snapshot while its local proxy switch is on;
// that snapshot must still carry the selected node or the preference would be
// saved successfully but never reach dae.
func ApplyNodePreferences(policy []model.Rule, prefs map[string]string, nodes []model.Node) []model.Rule {
	for i := range policy {
		r := &policy[i]
		if r.SourceType == "system" || r.SourceType == "user" || r.SourceType == "admin" {
			continue
		}
		applyNodePreference(r, prefs, nodes)
	}
	return policy
}

func applyNodePreference(r *model.Rule, prefs map[string]string, nodes []model.Node) {
	if r.Action == "BLOCK" {
		return
	}
	if value := prefs[r.Category]; value != "" && selection.Valid(value, nodes) {
		r.Action = selection.Action(value)
	}
}

func (e *Engine) CompilePolicy(policy []model.Rule) []model.CompiledRule {
	out := make([]model.CompiledRule, 0, len(policy))
	for _, r := range sortedRules(policy) {
		if r.Enabled {
			out = append(out, toCompiled(r, "ordered policy"))
		}
	}
	return out
}

func (e *Engine) ExplainPolicy(profile string, policy []model.Rule, q Query) model.ExplainResult {
	result := model.ExplainResult{Profile: normalizeProfile(profile), Fallback: fallbackFor(profile)}
	for _, r := range sortedRules(policy) {
		if r.Enabled && scopeMatches(r, q) && matchRule(r, q) {
			result.Candidates = append(result.Candidates, toCompiled(r, "matched "+r.MatchType))
		}
	}
	if len(result.Candidates) > 0 {
		result.Matched = &result.Candidates[0]
	}
	return result
}
