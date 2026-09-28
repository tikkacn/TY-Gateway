package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"tygateway/internal/frpauth"
)

func TestFetchAndCacheRoster(t *testing.T) {
	roster := frpauth.Roster{GeneratedAt: time.Now().UTC(), Entries: []frpauth.Entry{{DeviceID: "device-01", Port: 22001, CredentialHash: strings.Repeat("a", 64)}}}
	const token = "test-only-dedicated-roster-token-long-value"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(roster)
	}))
	defer server.Close()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := fetchRoster(context.Background(), server.Client(), server.URL+"/api/v1/frp/roster", tokenFile)
	if err != nil || len(got.Entries) != 1 {
		t.Fatalf("fetch: %#v, %v", got, err)
	}
	cache := filepath.Join(dir, "cache", "roster.json")
	if err := writeCache(cache, got); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadCache(cache)
	if err != nil || loaded.Validate(time.Now(), time.Hour, 22001, 22099) != nil {
		t.Fatalf("cache: %#v, %v", loaded, err)
	}
	if info, err := os.Stat(cache); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) {
		t.Fatalf("cache permissions: %v, %v", info, err)
	}
	if err := os.WriteFile(tokenFile, []byte("wrong"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fetchRoster(context.Background(), server.Client(), server.URL+"/api/v1/frp/roster", tokenFile); err == nil {
		t.Fatal("invalid token was accepted")
	}
}

func TestSettingsRejectsNonHTTPSRosterAndPublicListen(t *testing.T) {
	t.Setenv("TY_FRP_ROSTER_URL", "http://example.invalid/api/v1/frp/roster")
	t.Setenv("TY_FRP_ROSTER_TOKEN_FILE", "token")
	t.Setenv("TY_FRP_SERVER_AUTH_TOKEN_FILE", "server-token")
	if _, err := settingsFromEnv(); err == nil {
		t.Fatal("HTTP roster URL accepted")
	}
	t.Setenv("TY_FRP_ROSTER_URL", "https://example.invalid/api/v1/frp/roster")
	t.Setenv("TY_FRP_SERVER_AUTH_TOKEN_FILE", "server-token")
	t.Setenv("TY_FRP_AUTH_LISTEN", "0.0.0.0:9081")
	if _, err := settingsFromEnv(); err == nil {
		t.Fatal("public plugin listener accepted")
	}
}

func TestSettingsUseUnifiedRangeAndRejectPartialPool(t *testing.T) {
	t.Setenv("TY_FRP_ROSTER_URL", "https://cloud.example.test/api/v1/frp/roster")
	t.Setenv("TY_FRP_ROSTER_TOKEN_FILE", "/tmp/roster-token")
	t.Setenv("TY_FRP_SERVER_AUTH_TOKEN_FILE", "/etc/frp/server-auth-token")
	t.Setenv("TY_FRP_AUTH_LISTEN", "127.0.0.1:9081")
	t.Setenv("TY_FRP_PORT_START", "")
	t.Setenv("TY_FRP_PORT_END", "")
	cfg, err := settingsFromEnv()
	if err != nil || cfg.portStart != 22000 || cfg.portEnd != 22999 {
		t.Fatalf("plugin and Cloud auto-FRP defaults disagree: %#v, %v", cfg, err)
	}
	t.Setenv("TY_FRP_PORT_START", "22100")
	t.Setenv("TY_FRP_PORT_END", "22999")
	if _, err := settingsFromEnv(); err == nil {
		t.Fatal("plugin accepted a partial port pool")
	}
}

func TestLoadServerAuthTokenRequiresPrivateStrongSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "frps-token")
	const token = "server-only-test-token-0123456789abcdef"
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadServerAuthToken(path)
	if err != nil || got != token {
		t.Fatalf("load private server token: got=%q err=%v", got, err)
	}
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadServerAuthToken(path); err == nil {
		t.Fatal("short server auth token accepted")
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, []byte(token), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadServerAuthToken(path); err == nil {
			t.Fatal("publicly readable server auth token accepted")
		}
	}
}
