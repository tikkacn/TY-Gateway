package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/model"
)

type credential struct {
	DeviceID     string `json:"device_id"`
	DeviceSecret string `json:"device_secret"`
}
type persisted struct {
	Server  string                `json:"server,omitempty"`
	Devices map[string]credential `json:"devices"`
}
type registerResponse struct {
	Device struct {
		Serial       string `json:"serial"`
		DeviceNumber int64  `json:"device_number"`
	} `json:"device"`
	Credentials credential `json:"credentials"`
}

func main() {
	server := flag.String("server", "http://127.0.0.1:9080", "TY Cloud base URL")
	count := flag.Int("count", 1, "number of simulated devices")
	interval := flag.Duration("interval", 10*time.Second, "heartbeat interval")
	duration := flag.Duration("duration", 30*time.Second, "test duration")
	statePath := flag.String("state", "work/simulator-state.json", "local credential state file")
	controlOnly := flag.Bool("control-only", false, "check configuration, status and supported command acknowledgements without load testing")
	flag.Parse()
	if *count < 1 || *count > 1000 {
		fatal("count must be between 1 and 1000")
	}
	if *interval <= 0 || *duration <= 0 {
		fatal("interval and duration must be positive")
	}
	state := loadState(*statePath)
	if state.Server != "" && state.Server != *server {
		fatal("credential file belongs to another server")
	}
	state.Server = *server
	if state.Devices == nil {
		state.Devices = map[string]credential{}
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxIdleConns: 200, MaxIdleConnsPerHost: 100, IdleConnTimeout: 30 * time.Second}}
	base := *server
	type device struct {
		mac    string
		cred   credential
		number int64
	}
	devices := make([]device, 0, *count)
	for i := 0; i < *count; i++ {
		mac := makeMAC(i + 1)
		if c, ok := state.Devices[mac]; ok {
			devices = append(devices, device{mac: mac, cred: c, number: int64(i + 1)})
			continue
		}
		rr, cred, err := register(context.Background(), client, base, mac)
		if err != nil {
			if c, ok := state.Devices[mac]; ok {
				cred = c
			} else {
				fatal("register %s: %v", mac, err)
			}
		} else {
			cred = rr.Credentials
			state.Devices[mac] = cred
			if err := saveState(*statePath, state); err != nil {
				fatal("could not persist registration")
			}
			fmt.Printf("registered serial=%s (database number visible in admin only)\n", rr.Device.Serial)
		}
		devices = append(devices, device{mac: mac, cred: cred, number: int64(i + 1)})
	}
	if err := saveState(*statePath, state); err != nil {
		fatal("save state: %v", err)
	}
	if *controlOnly {
		var wg sync.WaitGroup
		var failed, completed atomic.Int64
		for _, d := range devices {
			wg.Add(1)
			go func(c credential) {
				defer wg.Done()
				if err := checkControl(client, base, c); err != nil {
					failed.Add(1)
				} else {
					completed.Add(1)
				}
			}(d.cred)
		}
		wg.Wait()
		fmt.Printf("control-check devices=%d passed=%d failed=%d\n", len(devices), completed.Load(), failed.Load())
		if failed.Load() > 0 {
			os.Exit(1)
		}
		return
	}
	var sent, failed int64
	var latencyMu sync.Mutex
	latencies := []time.Duration{}
	started := time.Now()
	fmt.Printf("load-start devices=%d utc=%s\n", *count, started.UTC().Format(time.RFC3339))
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	var wg sync.WaitGroup
	for _, d := range devices {
		d := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(*interval)
			defer ticker.Stop()
			for {
				if ctx.Err() != nil {
					return
				}
				requestStart := time.Now()
				// End stops scheduling, not in-flight requests. Drain requests with
				// their own timeout so shutdown is not misreported as overload.
				if err := heartbeat(context.Background(), client, base, d.cred); err != nil {
					atomic.AddInt64(&failed, 1)
					if strings.HasPrefix(err.Error(), "HTTP ") {
						fmt.Printf("simulator index %03d heartbeat failed (%s)\n", d.number, err.Error())
					} else {
						fmt.Printf("simulator index %03d heartbeat failed (%T)\n", d.number, err)
					}
				} else {
					atomic.AddInt64(&sent, 1)
				}
				latencyMu.Lock()
				latencies = append(latencies, time.Since(requestStart))
				latencyMu.Unlock()
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	wg.Wait()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) > 0 {
		fmt.Printf("latency_ms p50=%d p95=%d max=%d\n", latencies[len(latencies)/2].Milliseconds(), latencies[(len(latencies)-1)*95/100].Milliseconds(), latencies[len(latencies)-1].Milliseconds())
	}
	fmt.Printf("simulator complete: devices=%d attempted=%d successful=%d failures=%d schedule_duration=%s elapsed=%s\n", *count, sent+failed, sent, failed, *duration, time.Since(started))
	if failed > 0 {
		os.Exit(1)
	}
}

func register(ctx context.Context, client *http.Client, base, mac string) (registerResponse, credential, error) {
	body, _ := json.Marshal(map[string]string{"mac": mac, "firmware_version": "0.1.0-sim", "agent_version": "0.1.0-sim", "kernel_version": "simulated", "hardware_version": "simulated"})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/devices/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return registerResponse{}, credential{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return registerResponse{}, credential{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out registerResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return out, credential{}, err
	}
	return out, out.Credentials, nil
}
func heartbeat(ctx context.Context, client *http.Client, base string, c credential) error {
	body, _ := json.Marshal(map[string]string{"firmware_version": "0.1.0-sim", "agent_version": "0.1.0-sim", "kernel_version": "simulated", "hardware_version": "simulated", "status": "ok"})
	return signedJSON(ctx, client, http.MethodPost, base+"/api/v1/device/"+c.DeviceID+"/heartbeat", body, c)
}
func signedJSON(ctx context.Context, client *http.Client, method, target string, body []byte, c credential) error {
	_, err := signedResult(ctx, client, method, target, body, c)
	return err
}
func signedResult(ctx context.Context, client *http.Client, method, target string, body []byte, c credential) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	ts := time.Now().Unix()
	nonce := fmt.Sprintf("%d-%d", ts, time.Now().UnixNano())
	key := auth.SecretHash(c.DeviceSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TY-Device", c.DeviceID)
	req.Header.Set("X-TY-Timestamp", fmt.Sprint(ts))
	req.Header.Set("X-TY-Nonce", nonce)
	req.Header.Set("X-TY-Signature", auth.Sign(method, req.URL.Path, body, ts, nonce, key))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return data, nil
}

func effectiveRules(c model.DeviceConfig, elapsed time.Duration) []model.CompiledRule {
	if c.ValidUntil != nil && !c.ServerTime.Add(elapsed).Before(*c.ValidUntil) {
		return c.BaseRules
	}
	return c.Rules
}
func checkControl(client *http.Client, base string, c credential) error {
	ctx := context.Background()
	path := base + "/api/v1/device/" + c.DeviceID
	data, err := signedResult(ctx, client, http.MethodGet, path+"/config", nil, c)
	if err != nil {
		return err
	}
	var config model.DeviceConfig
	if json.Unmarshal(data, &config) != nil || config.Device.ID != c.DeviceID || config.ServerTime.IsZero() || len(config.BaseRules) == 0 {
		return fmt.Errorf("invalid configuration")
	}
	_ = effectiveRules(config, 0) // Simulator applies policy only, never routes traffic.
	if err = signedJSON(ctx, client, http.MethodPost, path+"/status", []byte(`{"status":"ok"}`), c); err != nil {
		return err
	}
	data, err = signedResult(ctx, client, http.MethodGet, path+"/commands", nil, c)
	if err != nil {
		return err
	}
	var commands struct {
		Commands []model.Command `json:"commands"`
	}
	if err = json.Unmarshal(data, &commands); err != nil {
		return err
	}
	for _, cmd := range commands.Commands {
		if cmd.Command == "reload_config" {
			_, err = signedResult(ctx, client, http.MethodGet, path+"/config", nil, c)
		} else if cmd.Command == "report_status" {
			err = signedJSON(ctx, client, http.MethodPost, path+"/status", []byte(`{"status":"ok"}`), c)
		} else {
			continue
		}
		if err != nil {
			return err
		}
		if err = signedJSON(ctx, client, http.MethodPost, path+"/commands/"+cmd.ID+"/ack", []byte(`{"status":"ok"}`), c); err != nil {
			return err
		}
	}
	return nil
}
func makeMAC(n int) string {
	return fmt.Sprintf("02:54:59:%02X:%02X:%02X", (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}
func loadState(path string) persisted {
	b, err := os.ReadFile(path)
	if err != nil {
		return persisted{Devices: map[string]credential{}}
	}
	var s persisted
	if json.Unmarshal(b, &s) != nil {
		s.Devices = map[string]credential{}
	}
	return s
}
func saveState(path string, s persisted) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".simulator-state-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func fatal(format string, args ...any) { fmt.Printf("error: "+format+"\n", args...); os.Exit(1) }
