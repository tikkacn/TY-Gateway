package main

import (
	"testing"
	"time"
	"tygateway/internal/model"
)

func TestOfflineOverrideExpires(t *testing.T) {
	now := time.Now()
	until := now.Add(time.Minute)
	c := model.DeviceConfig{ServerTime: now, ValidUntil: &until, Rules: []model.CompiledRule{{Action: "PROXY"}}, BaseRules: []model.CompiledRule{{Action: "DIRECT"}}}
	if effectiveRules(c, 30*time.Second)[0].Action != "PROXY" {
		t.Fatal("override not active")
	}
	if effectiveRules(c, time.Minute)[0].Action != "DIRECT" {
		t.Fatal("offline expiry ignored")
	}
}
