package store

import (
	"context"
	"errors"
	"testing"

	"tygateway/internal/model"
)

func TestReplaceCustomerSettingsIsAtomicAndPreservesAdminRules(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	d, _, err := s.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:99"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRescueSSHPort(ctx, d.ID, 22017); err != nil {
		t.Fatal(err)
	}
	deviceAuth, err := s.GetDeviceAuth(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := s.CreateRule(ctx, model.Rule{DeviceID: d.ID, Source: "admin", SourceType: "admin", MatchType: "domain_suffix", MatchValue: "managed.example", Action: "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.SaveCustomerRule(ctx, model.Rule{DeviceID: d.ID, MatchType: "domain_suffix", MatchValue: "old.example", Action: "DIRECT"})
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	replacement := []model.CustomerSettingRule{{MatchType: "domain_suffix", MatchValue: "new.example", Action: "PROXY"}}
	if _, err := s.ReplaceCustomerSettings(ctx, d.ID, d.ConfigVersion-1, replacement, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale replacement error=%v", err)
	}
	duplicate := append(append([]model.CustomerSettingRule{}, replacement...), replacement[0])
	if _, err := s.ReplaceCustomerSettings(ctx, d.ID, d.ConfigVersion, duplicate, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate replacement error=%v", err)
	}
	rules, err := s.ListCustomerRules(ctx, d.ID)
	if err != nil || len(rules) != 1 || rules[0].ID != old.ID {
		t.Fatalf("failed replacement changed customer rules: %#v %v", rules, err)
	}
	version, err := s.ReplaceCustomerSettings(ctx, d.ID, d.ConfigVersion, replacement, nil)
	if err != nil || version != d.ConfigVersion+1 {
		t.Fatalf("replacement version=%d error=%v", version, err)
	}
	rules, err = s.ListCustomerRules(ctx, d.ID)
	if err != nil || len(rules) != 1 || rules[0].MatchValue != "new.example" {
		t.Fatalf("replacement rules=%#v error=%v", rules, err)
	}
	all, err := s.ListRules(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	foundAdmin := false
	for _, rule := range all {
		foundAdmin = foundAdmin || rule.ID == admin.ID
	}
	if !foundAdmin {
		t.Fatal("customer replacement removed administrator rule")
	}
	if _, err := s.ReplaceCustomerSettings(ctx, d.ID, version, nil, nil); err != nil {
		t.Fatal(err)
	}
	rules, err = s.ListCustomerRules(ctx, d.ID)
	if err != nil || len(rules) != 0 {
		t.Fatalf("customer reset rules=%#v error=%v", rules, err)
	}
	after, err := s.GetDevice(ctx, d.ID)
	if err != nil || after.ID != d.ID || after.Serial != d.Serial || after.MAC != d.MAC || after.RescueSSHPort != 22017 {
		t.Fatalf("customer reset changed device registration or rescue port: %#v %v", after, err)
	}
	afterAuth, err := s.GetDeviceAuth(ctx, d.ID)
	if err != nil || afterAuth.SecretHash != deviceAuth.SecretHash {
		t.Fatalf("customer reset changed device credentials: %#v %v", afterAuth, err)
	}
}
