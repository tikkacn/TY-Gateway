package providers

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tygateway/internal/identity"
	"tygateway/internal/model"
)

var ErrNoRules = errors.New("provider contained no supported rules")

type Category struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

func Catalog() []Category {
	ids := []string{"China", "Google", "YouTube", "OpenAI", "Telegram", "GitHub", "Netflix", "Disney", "Microsoft", "Apple", "Steam", "Advertising"}
	out := make([]Category, 0, len(ids))
	for _, id := range ids {
		out = append(out, Category{ID: id, Name: id, Description: "Provider category; strategy is mapped separately to an outbound group."})
	}
	return out
}

// ParseClashRules accepts the common provider format:
// DOMAIN-SUFFIX,example.com,Proxy
// DOMAIN,example.com,DIRECT
// IP-CIDR,1.2.3.0/24,Proxy,no-resolve
// Unsupported directives are ignored deliberately. A failed import must never replace LKG.
func ParseClashRules(provider, content string) ([]model.Rule, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var rules []model.Rule
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		kind := strings.ToUpper(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if value == "" {
			continue
		}
		matchType := ""
		switch kind {
		case "DOMAIN":
			matchType = "domain"
		case "DOMAIN-SUFFIX":
			matchType = "domain_suffix"
		case "DOMAIN-KEYWORD":
			matchType = "domain_keyword"
		case "IP-CIDR", "IP-CIDR6":
			matchType = "cidr"
		default:
			continue
		}
		action := "AUTO"
		if len(parts) >= 3 {
			action = normalizeAction(parts[2])
		}
		rules = append(rules, model.Rule{ID: identity.NewID(), Source: provider, SourceType: "provider", Category: provider, MatchType: matchType, MatchValue: value, Action: action, Priority: 400 + lineNo, Enabled: true})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, ErrNoRules
	}
	return rules, nil
}

func normalizeAction(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	switch v {
	case "DIRECT", "REJECT", "BLOCK", "PROXY", "AUTO", "HK", "JP", "SG", "US", "TW":
		if v == "REJECT" {
			return "BLOCK"
		}
		return v
	default:
		return "AUTO"
	}
}

func ValidateProviderName(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("provider is required")
	}
	if len(v) > 80 {
		return errors.New("provider name too long")
	}
	return nil
}
func Summary(rules []model.Rule) map[string]int {
	result := map[string]int{}
	for _, r := range rules {
		result[r.MatchType]++
	}
	return result
}
func FormatRuleCount(rules []model.Rule) string { return strconv.Itoa(len(rules)) }
func Errorf(provider string, err error) error   { return fmt.Errorf("provider %s: %w", provider, err) }
