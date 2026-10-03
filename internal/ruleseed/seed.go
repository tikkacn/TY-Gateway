// Package ruleseed contains public, secret-free rule seeds carried by the
// signed software release. A seed is never a device configuration or proof
// that a subscription/DAE policy has been applied.
package ruleseed

import (
	"bytes"
	"compress/gzip"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/rules"
)

//go:embed data/*
var files embed.FS

var Profiles = []string{"managed_loyal", "managed_meta", "managed_gfw", "managed_geo"}

type Package struct {
	Profile     string               `json:"profile"`
	Name        string               `json:"name"`
	Version     string               `json:"version"`
	PublishedAt string               `json:"published_at"`
	Categories  []string             `json:"categories"`
	Rules       []model.CompiledRule `json:"rules"`
}

func ValidVersion(version string) bool {
	decoded, err := hex.DecodeString(version)
	return err == nil && len(decoded) == 32
}

func KnownProfile(profile string) bool {
	for _, id := range Profiles {
		if id == profile {
			return true
		}
	}
	return false
}

// Validate is also the build-time gate. Only public provider rules may enter
// the release; node endpoints, customer rules and device credentials cannot.
func Validate(p Package) error {
	if !KnownProfile(p.Profile) || p.Name == "" || !ValidVersion(p.Version) || len(p.Categories) == 0 || len(p.Categories) > 32 || len(p.Rules) == 0 || len(p.Rules) > 12000 {
		return errors.New("invalid public rule seed")
	}
	if _, err := time.Parse(time.RFC3339Nano, p.PublishedAt); err != nil {
		return err
	}
	ids := make(map[string]bool)
	for _, r := range p.Rules {
		if r.RuleID == "" || ids[r.RuleID] || r.Source != p.Profile || r.SourceType != "provider" || r.Match == "" || (r.Action != "DIRECT" && r.Action != "PROXY" && r.Action != "BLOCK") {
			return errors.New("rule seed contains non-public or invalid rules")
		}
		ids[r.RuleID] = true
	}
	_, err := rules.RenderDaeManaged(model.DaePolicy{Profile: p.Profile, Rules: p.Rules, Interface: "eth0", ProxyEnabled: true, SubscriptionPresent: true})
	return err
}

var once sync.Once
var packages map[string]Package

func load() {
	packages = make(map[string]Package)
	for _, profile := range Profiles {
		raw, err := files.ReadFile("data/" + profile + ".json.gz")
		if err != nil {
			continue
		}
		reader, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			continue
		}
		decoded, err := io.ReadAll(io.LimitReader(reader, (8<<20)+1))
		_ = reader.Close()
		if err != nil || len(decoded) > 8<<20 {
			continue
		}
		var p Package
		if json.Unmarshal(decoded, &p) != nil || p.Profile != profile || Validate(p) != nil {
			continue
		}
		packages[profile] = p
	}
}

func Get(profile string) (Package, bool) {
	once.Do(load)
	p, ok := packages[profile]
	return p, ok // callers must not modify the embedded slices
}

func Versions() map[string]string {
	out := make(map[string]string)
	for _, id := range Profiles {
		if p, ok := Get(id); ok {
			out[id] = p.Version
		}
	}
	return out
}

func Catalog() []map[string]any {
	out := make([]map[string]any, 0, len(Profiles))
	for _, id := range Profiles {
		if p, ok := Get(id); ok {
			out = append(out, map[string]any{"id": id, "name": p.Name, "version": p.Version, "published_at": p.PublishedAt, "categories": p.Categories, "available": true, "origin": "bundled"})
		}
	}
	return out
}

// Compact removes only repeated match expressions. The server still supplies
// every rule's order, action, priority and defaults; personal/system rules are
// never omitted. Older clients or different seed versions receive full rules.
func Compact(config model.DeviceConfig, versions map[string]string) model.DeviceConfig {
	if !KnownProfile(config.Profile) || !ValidVersion(config.RulePackageVersion) || versions[config.Profile] != config.RulePackageVersion {
		return config
	}
	count := 0
	compact := func(input []model.CompiledRule) []model.CompiledRule {
		out := append([]model.CompiledRule(nil), input...)
		for i := range out {
			if out[i].Source == config.Profile && out[i].SourceType == "provider" {
				out[i].Match = ""
				count++
			}
		}
		return out
	}
	config.Rules, config.BaseRules = compact(config.Rules), compact(config.BaseRules)
	if count > 0 {
		config.RuleSeedVersion = config.RulePackageVersion
	}
	return config
}

// Hydrate changes only missing expressions, preserving the exact wire order
// and selections. Never use an older bundled rule for a newer cloud version.
func Hydrate(config model.DeviceConfig) (model.DeviceConfig, error) {
	if config.RuleSeedVersion == "" {
		return config, nil
	}
	p, ok := Get(config.Profile)
	if !ok || p.Version != config.RuleSeedVersion || config.RulePackageVersion != p.Version {
		return config, errors.New("cloud rule seed version is unavailable")
	}
	byID := make(map[string]model.CompiledRule, len(p.Rules))
	for _, r := range p.Rules {
		byID[r.RuleID] = r
	}
	fill := func(input []model.CompiledRule) ([]model.CompiledRule, error) {
		out := append([]model.CompiledRule(nil), input...)
		for i := range out {
			if out[i].Match != "" {
				continue
			}
			seed, exists := byID[out[i].RuleID]
			if !exists || out[i].Source != p.Profile || out[i].SourceType != "provider" || out[i].Category != seed.Category || out[i].Priority != seed.Priority {
				return nil, errors.New("cloud rule seed reference is invalid")
			}
			out[i].Match = seed.Match
		}
		return out, nil
	}
	var err error
	if config.Rules, err = fill(config.Rules); err != nil {
		return config, err
	}
	if config.BaseRules, err = fill(config.BaseRules); err != nil {
		return config, err
	}
	config.RuleSeedVersion = "" // persisted snapshots are always self-contained
	return config, nil
}
