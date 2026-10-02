package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/nodeprobe"
)

const nodeProbeFile = "node-check.json"

type savedNodeProbe struct {
	URL       string             `json:"url"`
	Target    string             `json:"target"`
	Results   []nodeprobe.Result `json:"results"`
	CheckedAt time.Time          `json:"checked_at,omitempty"`
}
type nativeNodeProber interface {
	Probe(context.Context, nodeprobe.Request) ([]nodeprobe.Observation, error)
}

func (u unixDaeApplier) Probe(ctx context.Context, request nodeprobe.Request) ([]nodeprobe.Observation, error) {
	result, err := u.request(ctx, daeApplyRequest{ServiceAction: "probe", Probe: &request})
	if err != nil || result.Status != "ok" {
		return nil, errors.New("dae probe unavailable")
	}
	return result.Observations, nil
}
func defaultNodeProbe() savedNodeProbe {
	return savedNodeProbe{URL: nodeprobe.DefaultURL, Target: nodeprobe.DefaultURL + ",1.1.1.1", Results: []nodeprobe.Result{}}
}
func (a *agent) loadNodeProbe() (savedNodeProbe, error) {
	path := filepath.Join(a.stateDir, nodeProbeFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return defaultNodeProbe(), nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128<<10 {
		return savedNodeProbe{}, errors.New("测速设置文件不可读取。")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return savedNodeProbe{}, errors.New("测速设置文件不可读取。")
	}
	var saved savedNodeProbe
	if json.Unmarshal(data, &saved) != nil || nodeprobe.ValidateURL(saved.URL) != nil || nodeprobe.ValidateCompiled(saved.Target) != nil || !strings.HasPrefix(saved.Target, saved.URL+",") || len(saved.Results) > 256 {
		return savedNodeProbe{}, errors.New("测速设置文件无效，请核对设备配置。")
	}
	if saved.Results == nil {
		saved.Results = []nodeprobe.Result{}
	}
	return saved, nil
}
func (a *agent) localCheckTarget() string {
	saved, err := a.loadNodeProbe()
	if err != nil {
		return defaultNodeProbe().Target
	} // Corrupt metrics must not stop the proxy/rescue path.
	return saved.Target
}
func (a *agent) saveNodeProbe(saved savedNodeProbe) error {
	data, err := json.Marshal(saved)
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(a.stateDir, nodeProbeFile), data)
}
func probeResponse(saved savedNodeProbe, running bool) localControlResponse {
	var checkedAt *time.Time
	if !saved.CheckedAt.IsZero() {
		at := saved.CheckedAt
		checkedAt = &at
	}
	data, _ := json.Marshal(nodeprobe.State{URL: saved.URL, Results: saved.Results, CheckedAt: checkedAt, Running: running})
	return localControlResponse{Data: data}
}
func resolveCheckTarget(ctx context.Context, raw string) (string, error) {
	if nodeprobe.ValidateURL(raw) != nil {
		return "", errors.New("请使用公开 HTTP/HTTPS 测速地址（80/443），不能包含凭据、内网 IP 或特殊分隔符。")
	}
	if raw == nodeprobe.DefaultURL {
		return defaultNodeProbe().Target, nil
	}
	u, _ := url.Parse(raw)
	if addr, err := netip.ParseAddr(u.Hostname()); err == nil {
		return nodeprobe.Compile(raw, addr)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip4", u.Hostname())
	if err != nil || len(ips) == 0 {
		return "", errors.New("测速地址未解析到可用的公网 IPv4，请检查地址或使用默认地址。")
	}
	for _, ip := range ips {
		if !nodeprobe.PublicIPv4(ip) {
			return "", errors.New("测速域名解析包含内网或保留地址，已拒绝。")
		}
	}
	return nodeprobe.Compile(raw, ips[0])
}

func (a *agent) localNodeProbe(ctx context.Context, method, path string, body json.RawMessage) localControlResponse {
	if method == http.MethodGet && path == "/speed-test" {
		a.probeMu.Lock()
		defer a.probeMu.Unlock()
		saved, err := a.loadNodeProbe()
		if err != nil {
			return localControlResponse{Error: err.Error()}
		}
		return probeResponse(saved, a.probeRunning)
	}
	if method != http.MethodPost || (path != "/speed-test/settings" && path != "/speed-test/run") {
		return localControlResponse{Error: "测速操作不受支持。"}
	}
	// Do not queue a long diagnostic behind config reloads, or accept two runs.
	if !a.configMu.TryLock() {
		return localControlResponse{Error: "设备正在同步或应用配置，请稍后再测速。"}
	}
	defer a.configMu.Unlock()
	saved, err := a.loadNodeProbe()
	if err != nil {
		return localControlResponse{Error: err.Error()}
	}
	if path == "/speed-test/settings" {
		var input nodeprobe.Settings
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
			return localControlResponse{Error: "测速设置格式错误。"}
		}
		target, err := resolveCheckTarget(ctx, input.URL)
		if err != nil {
			return localControlResponse{Error: err.Error()}
		}
		next := savedNodeProbe{URL: input.URL, Target: target, Results: []nodeprobe.Result{}}
		if err := a.saveNodeProbe(next); err != nil {
			return localControlResponse{Error: "测速地址保存失败，旧设置未变。"}
		}
		a.stateMu.RLock()
		enabled := a.localProxyOn
		a.stateMu.RUnlock()
		if enabled {
			state := a.applyCachedPolicy(ctx, true)
			if state.Error != "" {
				if err := a.saveNodeProbe(saved); err != nil {
					return localControlResponse{Error: "测速地址应用失败且设置回滚失败，请检查设备存储。"}
				}
				recoveryCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				recovered := a.applyCachedPolicy(recoveryCtx, true)
				cancel()
				if recovered.Error != "" {
					return localControlResponse{Error: "测速地址应用失败，旧设置已保存但 dae 未确认恢复，请核对运行状态。"}
				}
				return localControlResponse{Error: "dae 未确认新测速地址，已恢复旧设置。"}
			}
		}
		return probeResponse(next, false)
	}
	a.stateMu.RLock()
	allowed := a.localProxyOn && a.proxyApplied && a.policyReady
	a.stateMu.RUnlock()
	if !allowed {
		return localControlResponse{Error: "请先确认科学上网已开启且 dae 已应用代理配置；测速不会自动开启代理。"}
	}
	active, err := a.daeApplier.ServiceActive(ctx)
	if err != nil || !active {
		return localControlResponse{Error: "dae 未在运行，不能读取真实节点测速。"}
	}
	prober, ok := a.daeApplier.(nativeNodeProber)
	if !ok {
		return localControlResponse{Error: "请升级本机 dae 辅助程序以支持测速。"}
	}
	snapshot, err := a.loadAppliedSnapshot()
	if err != nil {
		return localControlResponse{Error: "请先同步本机已验证的节点。"}
	}
	var inventory struct {
		Nodes []model.CustomerNode `json:"nodes"`
	}
	if json.Unmarshal(snapshot.Customer, &inventory) != nil || len(inventory.Nodes) == 0 || len(inventory.Nodes) > 256 {
		return localControlResponse{Error: "当前没有可测速的已验证节点。"}
	}
	request := nodeprobe.Request{}
	for _, node := range inventory.Nodes {
		request.Names = append(request.Names, node.Name)
	}
	a.probeMu.Lock()
	if time.Since(a.lastProbeStarted) < time.Minute {
		a.probeMu.Unlock()
		return localControlResponse{Error: "测速间隔至少 1 分钟，请稍后重试。"}
	}
	a.probeRunning, a.lastProbeStarted = true, time.Now()
	a.probeMu.Unlock()
	defer func() { a.probeMu.Lock(); a.probeRunning = false; a.probeMu.Unlock() }()
	observations, err := prober.Probe(ctx, request)
	if err != nil {
		return localControlResponse{Error: "无法完成 dae 测速或恢复诊断日志；旧结果保留，请检查辅助服务。"}
	}
	byName := map[string]nodeprobe.Observation{}
	for _, obs := range observations {
		byName[obs.Name] = obs
	}
	previous := make(map[string]nodeprobe.Result, len(saved.Results))
	for _, result := range saved.Results {
		previous[result.ID] = result
	}
	saved.Results = []nodeprobe.Result{}
	updated := 0
	for _, node := range inventory.Nodes {
		result := nodeprobe.Result{ID: node.ID, Status: "unknown"}
		// No new observation is not evidence that an earlier real result is
		// invalid. Keep its original timestamp; never stamp old latency as new.
		if old, ok := previous[node.ID]; ok && old.CheckedAt != nil && !old.CheckedAt.IsZero() && (old.Status == "failed" || old.Status == "ok" && old.LatencyMS != nil && *old.LatencyMS >= 0 && *old.LatencyMS <= 600000) {
			result = old
		}
		if obs, ok := byName[node.Name]; ok && !obs.CheckedAt.IsZero() && (obs.Status == "failed" || obs.Status == "ok" && obs.LatencyMS != nil && *obs.LatencyMS >= 0 && *obs.LatencyMS <= 600000) {
			at := obs.CheckedAt
			result.Status, result.LatencyMS, result.CheckedAt = obs.Status, obs.LatencyMS, &at
			updated++
		}
		saved.Results = append(saved.Results, result)
	}
	if updated == 0 {
		return localControlResponse{Error: "本次未获取到新的节点测速结果；上次结果已保留，请稍后重试。"}
	}
	saved.CheckedAt = time.Now().UTC()
	if a.saveNodeProbe(saved) != nil {
		return localControlResponse{Error: "测速完成，但结果未能保存；旧结果保留。"}
	}
	return probeResponse(saved, false)
}
