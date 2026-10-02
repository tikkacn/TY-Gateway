package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const configDownloadTimeout = 90 * time.Second

// Only idempotent config GETs retry, and only on a network timeout. Each
// attempt is freshly signed; auth, payload and DAE errors never retry here.
func (a *agent) downloadConfig(ctx context.Context) ([]byte, int, error) {
	path := "/api/v1/device/" + url.PathEscape(a.stateValue().DeviceID) + "/config"
	for attempt := 1; ; attempt++ {
		data, status, err := a.signedRequest(ctx, http.MethodGet, path, nil)
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return nil, status, nil // auth rejection wins even if its body timed out
		}
		var timeout net.Error
		if attempt >= 3 || ctx.Err() != nil || err == nil || (status != 0 && status/100 != 2) || !errors.As(err, &timeout) || !timeout.Timeout() {
			return data, status, err
		}
		a.client.CloseIdleConnections()
		if a.logger != nil {
			a.logger.Printf("config_sync stage=download_retry attempt=%d max_attempts=3", attempt+1)
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, status, ctx.Err()
		case <-timer.C:
		}
	}
}

func (a *agent) startConfigSync(forceSubscription, recheck bool) {
	a.stateMu.Lock()
	if a.syncRunning {
		a.stateMu.Unlock()
		return
	}
	a.syncRunning = true
	a.stateMu.Unlock()
	go func() {
		// Three download attempts plus customer state and an atomic DAE apply.
		ctx, cancel := context.WithTimeout(context.Background(), 450*time.Second)
		defer cancel()
		err := a.fetchConfigWithOptions(ctx, forceSubscription, recheck)
		if err != nil {
			if a.logger != nil {
				a.logger.Printf("background config sync failed: %s", safeSyncError(err))
			}
			a.configMu.Lock()
			a.stateMu.RLock()
			pending, generation := a.proxyPending && a.proxyWanted, a.proxyGeneration
			a.stateMu.RUnlock()
			if pending {
				a.stateMu.Lock()
				a.proxyPending = false
				a.stateMu.Unlock()
				state := a.rejectLocalProxyEnable(ctx, initializationError(err))
				a.stateMu.Lock()
				if a.proxyGeneration == generation && a.proxyWanted {
					a.proxyError = state.Error
				}
				a.stateMu.Unlock()
			}
			a.configMu.Unlock()
		}
		a.stateMu.Lock()
		a.syncRunning = false
		a.stateMu.Unlock()
	}()
}

func initializationError(err error) string {
	if safeSyncError(err) == "timeout" {
		return "首次配置下载超时，自动尝试未能完成；尚未开启代理，请稍后重试。"
	}
	if strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "HTTP 403") {
		return "云端设备鉴权未通过，代理保持关闭；请管理员检查设备注册状态。"
	}
	if strings.Contains(err.Error(), "subscription") {
		return "订阅未绑定或获取失败，代理保持关闭；请检查有效订阅。"
	}
	return "首次配置未能通过下载或 DAE 校验，代理保持关闭；请检查设备同步状态后重试。"
}

func (a *agent) currentProxyIntent(generation uint64) bool {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.proxyGeneration == generation
}

// Caller holds configMu. Never persist ON before DAE confirms native nodes.
func (a *agent) enableCachedProxy(ctx context.Context, generation uint64) localControlResponse {
	a.stateMu.Lock()
	if a.proxyGeneration != generation || !a.proxyWanted {
		a.stateMu.Unlock()
		return a.localControlStatus()
	}
	a.localProxyOn = true
	a.proxyPending = true
	a.stateMu.Unlock()
	state := a.applyCachedPolicy(ctx, true)
	if !a.currentProxyIntent(generation) {
		// A close may arrive while the helper was applying. Its intent wins.
		a.stateMu.RLock()
		wanted := a.proxyWanted
		a.stateMu.RUnlock()
		if !wanted {
			_ = a.daeApplier.Stop(ctx)
		}
		return a.localControlStatus()
	}
	if state.Error != "" || !state.Applied || !state.Ready || !state.Subscription || state.NodeCount <= 0 {
		return a.rejectLocalProxyEnable(ctx, "本机配置未通过 DAE 应用确认，代理保持关闭。")
	}
	a.stateMu.Lock()
	if a.proxyGeneration != generation || !a.proxyWanted {
		a.stateMu.Unlock()
		return a.localControlStatus()
	}
	err := a.saveLocalProxy(true)
	if err == nil {
		a.proxyPending, a.proxyError = false, ""
	}
	a.stateMu.Unlock()
	if err != nil {
		return a.rejectLocalProxyEnable(ctx, "本地开启状态无法安全保存；正在恢复直连。")
	}
	return a.localControlStatus()
}

func (a *agent) finishPendingEnable(ctx context.Context) {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	a.stateMu.RLock()
	pending, generation := a.proxyPending && a.proxyWanted, a.proxyGeneration
	a.stateMu.RUnlock()
	if !pending {
		return
	}
	state := a.enableCachedProxy(ctx, generation)
	if state.Error != "" && a.currentProxyIntent(generation) {
		a.stateMu.Lock()
		a.proxyPending, a.proxyError = false, state.Error
		a.stateMu.Unlock()
	}
}
