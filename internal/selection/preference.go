package selection

import (
	"regexp"
	"strings"

	"tygateway/internal/model"
)

// Preference is the compact, backwards-compatible value stored in the
// customer_node_preferences.node_id column (VARCHAR(64)). Node IDs reported by
// dae are 16 hex characters, so a primary plus two backups fit in that column.
type Preference struct {
	Kind   string
	Region string
	Nodes  []string
}

var regionOrder = []string{"HK", "TW", "SG", "JP", "KR", "US", "MY", "DE", "GB"}

var regionNames = map[string]string{
	"HK": "香港", "TW": "台湾", "SG": "新加坡", "JP": "日本", "KR": "韩国",
	"US": "美国", "MY": "马来西亚", "DE": "德国", "GB": "英国",
}

var regionPatterns = map[string]*regexp.Regexp{
	"HK": regexp.MustCompile(`(?i)香港|港澳|hong[ -]?kong|(^|[^a-z])(?:hk|hkg)([^a-z]|$)`),
	"TW": regexp.MustCompile(`(?i)台湾|台灣|台北|taiwan|(^|[^a-z])(?:tw|twn)([^a-z]|$)`),
	"SG": regexp.MustCompile(`(?i)新加坡|狮城|獅城|singapore|(^|[^a-z])(?:sg|sgp)([^a-z]|$)`),
	"JP": regexp.MustCompile(`(?i)日本|东京|東京|大阪|japan|(^|[^a-z])(?:jp|jpn)([^a-z]|$)`),
	"KR": regexp.MustCompile(`(?i)韩国|韓國|首尔|首爾|korea|(^|[^a-z])(?:kr|kor)([^a-z]|$)`),
	"US": regexp.MustCompile(`(?i)美国|美國|洛杉矶|洛杉磯|纽约|紐約|united[ -]?states|(^|[^a-z])(?:us|usa)([^a-z]|$)`),
	"MY": regexp.MustCompile(`(?i)马来西亚|馬來西亞|malaysia|(^|[^a-z])(?:my|mys)([^a-z]|$)`),
	"DE": regexp.MustCompile(`(?i)德国|德國|germany|(^|[^a-z])(?:de|deu)([^a-z]|$)`),
	"GB": regexp.MustCompile(`(?i)英国|英國|united[ -]?kingdom|(^|[^a-z])(?:uk|gb|gbr)([^a-z]|$)`),
}

func Regions() []string             { return append([]string(nil), regionOrder...) }
func RegionName(code string) string { return regionNames[code] }

// RegionForName is deliberately conservative: unrecognised names remain
// ungrouped, while still being available in the all-nodes pool.
func RegionForName(name string) string {
	for _, code := range regionOrder {
		if regionPatterns[code].MatchString(name) {
			return code
		}
	}
	return ""
}

func Parse(value string) (Preference, bool) {
	if len(value) > 64 {
		return Preference{}, false
	}
	switch value {
	case "":
		return Preference{Kind: "default"}, true
	case "@direct":
		return Preference{Kind: "direct"}, true
	case "@proxy":
		return Preference{Kind: "auto"}, true
	}
	if strings.HasPrefix(value, "@region:") {
		code := strings.TrimPrefix(value, "@region:")
		if regionNames[code] != "" {
			return Preference{Kind: "region", Region: code}, true
		}
		return Preference{}, false
	}
	if strings.HasPrefix(value, "@failover:") {
		ids := strings.Split(strings.TrimPrefix(value, "@failover:"), ",")
		if len(ids) < 2 || len(ids) > 3 {
			return Preference{}, false
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if id == "" || strings.ContainsAny(id, "\r\n:@, ") || seen[id] {
				return Preference{}, false
			}
			seen[id] = true
		}
		return Preference{Kind: "failover", Nodes: ids}, true
	}
	if value == "" || strings.HasPrefix(value, "@") || strings.ContainsAny(value, "\r\n:@, ") {
		return Preference{}, false
	}
	return Preference{Kind: "node", Nodes: []string{value}}, true
}

func IsSpecial(value string) bool {
	p, ok := Parse(value)
	return ok && p.Kind != "node" && p.Kind != "default"
}

// Valid requires an actual dae-validated node inventory for all node-bearing
// choices. It never trusts a region or a node name supplied by the browser.
func Valid(value string, nodes []model.Node) bool {
	p, ok := Parse(value)
	if !ok {
		return false
	}
	switch p.Kind {
	case "default", "direct", "auto":
		return true
	case "region":
		for _, node := range nodes {
			if RegionForName(node.Name) == p.Region {
				return true
			}
		}
		return false
	case "node", "failover":
		found := map[string]bool{}
		for _, node := range nodes {
			found[node.ID] = true
		}
		for _, id := range p.Nodes {
			if !found[id] {
				return false
			}
		}
		return true
	}
	return false
}

func Action(value string) string {
	p, ok := Parse(value)
	if !ok {
		return ""
	}
	switch p.Kind {
	case "direct":
		return "DIRECT"
	case "auto":
		return "PROXY"
	case "region":
		return "REGION:" + p.Region
	case "node":
		return "NODE:" + p.Nodes[0]
	case "failover":
		return "FAILOVER:" + strings.Join(p.Nodes, ",")
	}
	return ""
}
