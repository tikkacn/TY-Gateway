package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tygateway/internal/frpauth"
)

const maxRosterAge = 24 * time.Hour

type settings struct {
	listen    string
	rosterURL string
	tokenFile string
	cacheFile string
	portStart int
	portEnd   int
}

func main() {
	cfg, err := settingsFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	plugin := frpauth.NewPlugin(maxRosterAge, cfg.portStart, cfg.portEnd)
	if roster, err := loadCache(cfg.cacheFile); err == nil {
		if err := plugin.SetRoster(roster); err != nil {
			log.Print("cached FRP roster is unusable")
		}
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	refresh := func(ctx context.Context) error {
		roster, err := fetchRoster(ctx, client, cfg.rosterURL, cfg.tokenFile)
		if err != nil {
			return err
		}
		if err := roster.Validate(time.Now().UTC(), maxRosterAge, cfg.portStart, cfg.portEnd); err != nil {
			return err
		}
		if err := plugin.SetRoster(roster); err != nil {
			return err
		}
		if err := writeCache(cfg.cacheFile, roster); err != nil {
			return fmt.Errorf("roster active in memory but cache was not saved: %w", err)
		}
		return nil
	}
	if err := refresh(context.Background()); err != nil {
		log.Printf("initial FRP roster refresh failed: %v", err)
	}
	if !plugin.Ready() {
		log.Fatal("no fresh FRP roster; refusing to start")
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := refresh(context.Background()); err != nil {
				log.Printf("FRP roster refresh failed: %v", err)
			}
		}
	}()
	log.Printf("TY FRP authorization listening on %s", cfg.listen)
	server := &http.Server{Addr: cfg.listen, Handler: plugin, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	log.Fatal(server.ListenAndServe())
}

func settingsFromEnv() (settings, error) {
	cfg := settings{listen: "127.0.0.1:9081", rosterURL: os.Getenv("TY_FRP_ROSTER_URL"), tokenFile: os.Getenv("TY_FRP_ROSTER_TOKEN_FILE"), cacheFile: os.Getenv("TY_FRP_ROSTER_CACHE"), portStart: 22001, portEnd: 22099}
	if v := os.Getenv("TY_FRP_AUTH_LISTEN"); v != "" {
		cfg.listen = v
	}
	if v := os.Getenv("TY_FRP_PORT_START"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return cfg, errors.New("invalid TY_FRP_PORT_START")
		}
		cfg.portStart = p
	}
	if v := os.Getenv("TY_FRP_PORT_END"); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return cfg, errors.New("invalid TY_FRP_PORT_END")
		}
		cfg.portEnd = p
	}
	if cfg.cacheFile == "" {
		cfg.cacheFile = "/var/lib/ty-frp-auth/roster.json"
	}
	u, err := url.Parse(cfg.rosterURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || u.Path != "/api/v1/frp/roster" || cfg.tokenFile == "" || cfg.portStart < 1 || cfg.portStart > cfg.portEnd || cfg.portEnd > 65535 {
		return cfg, errors.New("invalid FRP authorization settings")
	}
	if !strings.HasPrefix(cfg.listen, "127.0.0.1:") {
		return cfg, errors.New("FRP authorization plugin must listen on 127.0.0.1")
	}
	return cfg, nil
}

func fetchRoster(ctx context.Context, client *http.Client, endpoint, tokenFile string) (frpauth.Roster, error) {
	info, err := os.Lstat(tokenFile)
	if err != nil {
		return frpauth.Roster{}, err
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return frpauth.Roster{}, errors.New("FRP roster token file permissions are too broad")
	}
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return frpauth.Roster{}, err
	}
	token := strings.TrimSpace(string(tokenBytes))
	if len(token) < 32 {
		return frpauth.Roster{}, errors.New("FRP roster token is invalid")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return frpauth.Roster{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return frpauth.Roster{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return frpauth.Roster{}, fmt.Errorf("roster HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return frpauth.Roster{}, errors.New("FRP roster response is too large")
	}
	var roster frpauth.Roster
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&roster); err != nil {
		return frpauth.Roster{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return frpauth.Roster{}, errors.New("FRP roster response has trailing data")
	}
	return roster, nil
}

func loadCache(path string) (frpauth.Roster, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return frpauth.Roster{}, err
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return frpauth.Roster{}, errors.New("FRP roster cache is not private")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return frpauth.Roster{}, err
	}
	if len(data) > 1<<20 {
		return frpauth.Roster{}, errors.New("FRP roster cache is too large")
	}
	var roster frpauth.Roster
	err = json.Unmarshal(data, &roster)
	return roster, err
}

func writeCache(path string, roster frpauth.Roster) error {
	data, err := json.Marshal(roster)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("FRP roster cache directory is not private")
	}
	f, err := os.CreateTemp(dir, ".roster-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
