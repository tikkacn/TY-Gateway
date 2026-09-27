package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/rules"
	"tygateway/internal/subscription"
)

const (
	socketPath       = "/run/ty-gateway-dae-helper.sock"
	configPath       = "/etc/dae/config.dae"
	managedDir       = "/etc/dae/ty-gateway"
	managedPath      = managedDir + "/managed.dae"
	subscriptionPath = managedDir + "/subscription.raw"
	backupPath       = "/etc/dae/config.dae.ty-gateway-before"
	daeUA            = "dae/v2.0.0 (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)"
)

type applyRequest struct {
	ManageSubscription bool                   `json:"manage_subscription"`
	Subscription       *model.DaeSubscription `json:"subscription,omitempty"`
	Policy             *model.DaePolicy       `json:"policy,omitempty"`
	RollbackToken      string                 `json:"rollback_token,omitempty"`
	ServiceAction      string                 `json:"service_action,omitempty"`
}

type applyResponse struct {
	Status        string               `json:"status"`
	NodeCount     int                  `json:"node_count"`
	Nodes         []model.CustomerNode `json:"nodes,omitempty"`
	PolicyStatus  string               `json:"policy_status,omitempty"`
	ErrorCode     string               `json:"error_code,omitempty"`
	RollbackToken string               `json:"rollback_token,omitempty"`
	ServiceActive bool                 `json:"service_active"`
}

type snapshot struct {
	data   []byte
	exists bool
}

var applyMu sync.Mutex

var lastAppliedBackup struct {
	token                string
	config, managed, sub snapshot
}

const nativeCountGroupPrefix = "ty_gateway_native_count_probe_"

func main() {
	if err := serve(socketPath); err != nil {
		log.Printf("dae helper stopped: %v", err)
		os.Exit(1)
	}
}

func serve(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return errors.New("cannot prepare helper socket")
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return errors.New("cannot listen on helper socket")
	}
	defer func() { _ = listener.Close(); _ = os.Remove(path) }()
	if err := os.Chmod(path, 0660); err != nil {
		return errors.New("cannot protect helper socket")
	}
	group, err := user.LookupGroup("tygateway")
	if err != nil {
		return errors.New("tygateway group is unavailable")
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || os.Chown(path, 0, gid) != nil {
		return errors.New("cannot assign helper socket group")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return errors.New("helper socket accept failed")
		}
		go serveConnection(conn)
	}
}

func serveConnection(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(115 * time.Second))
	var request applyRequest
	if err := json.NewDecoder(io.LimitReader(conn, 16<<20)).Decode(&request); err != nil {
		writeResponse(conn, applyResponse{Status: "error", ErrorCode: "invalid_request"})
		return
	}
	// Accept the previous Agent protocol during a rolling package upgrade.
	if !request.ManageSubscription && request.Policy == nil && request.Subscription != nil {
		request.ManageSubscription = true
	}
	writeResponse(conn, apply(request))
}

func writeResponse(w io.Writer, value applyResponse) {
	_ = json.NewEncoder(w).Encode(value)
}

func apply(request applyRequest) applyResponse {
	// Status checks are read-only and must not queue behind a long config
	// validation or DAE reload. The Agent uses a short deadline for this probe.
	if request.ServiceAction == "status" {
		if request.ManageSubscription || request.Subscription != nil || request.Policy != nil || request.RollbackToken != "" {
			return applyResponse{Status: "error", ErrorCode: "invalid_request"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dae")
		return applyResponse{Status: "ok", ServiceActive: err == nil}
	}
	applyMu.Lock()
	defer applyMu.Unlock()
	if request.ServiceAction != "" {
		if request.ManageSubscription || request.Subscription != nil || request.Policy != nil || request.RollbackToken != "" {
			return applyResponse{Status: "error", ErrorCode: "invalid_request"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		switch request.ServiceAction {
		case "stop":
			if _, err := run(ctx, "/usr/bin/systemctl", "disable", "--now", "dae"); err != nil {
				return applyResponse{Status: "error", ErrorCode: "dae_stop_failed"}
			}
			if _, err := run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dae"); err == nil {
				return applyResponse{Status: "error", ErrorCode: "dae_stop_failed", ServiceActive: true}
			}
			return applyResponse{Status: "stopped"}
		default:
			return applyResponse{Status: "error", ErrorCode: "invalid_request"}
		}
	}
	if request.RollbackToken != "" {
		if request.RollbackToken != lastAppliedBackup.token || request.ManageSubscription || request.Policy != nil || request.Subscription != nil {
			return applyResponse{Status: "error", ErrorCode: "rollback_unavailable"}
		}
		if err := restore(configPath, lastAppliedBackup.config); err != nil {
			return applyResponse{Status: "error", ErrorCode: "rollback_failed"}
		}
		if err := restore(managedPath, lastAppliedBackup.managed); err != nil {
			return applyResponse{Status: "error", ErrorCode: "rollback_failed"}
		}
		if err := restore(subscriptionPath, lastAppliedBackup.sub); err != nil {
			return applyResponse{Status: "error", ErrorCode: "rollback_failed"}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// A direct-only policy can be staged while dae is intentionally
		// stopped. Its rollback only needs to restore the files.
		if _, err := run(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dae"); err == nil {
			if _, err := run(ctx, "/usr/bin/systemctl", "reload", "dae"); err != nil {
				return applyResponse{Status: "error", ErrorCode: "rollback_failed"}
			}
		}
		lastAppliedBackup.token = ""
		return applyResponse{Status: "reverted", PolicyStatus: "reverted"}
	}
	directive := request.Subscription
	if !request.ManageSubscription && request.Policy == nil {
		return applyResponse{Status: "error", ErrorCode: "invalid_request"}
	}

	if err := ensureRegular(configPath); err != nil {
		return applyResponse{Status: "error", ErrorCode: "dae_config_missing"}
	}
	var candidate []byte
	filterCandidate := false
	if request.ManageSubscription && directive != nil {
		if !validSubscriptionID(directive.ID) {
			return applyResponse{Status: "error", ErrorCode: "invalid_subscription"}
		}
		if err := subscription.ValidateURL(directive.URL, false); err != nil {
			return applyResponse{Status: "error", ErrorCode: "invalid_subscription"}
		}
		var err error
		candidate, err = subscription.FetchPayload(context.Background(), directive.URL, false, daeUA, 10<<20)
		if err != nil {
			return applyResponse{Status: "error", ErrorCode: "subscription_fetch_failed"}
		}
		filterCandidate = true
	}

	configBefore, err := readSnapshot(configPath, 1<<20)
	if err != nil {
		return applyResponse{Status: "error", ErrorCode: "dae_config_unavailable"}
	}
	managedBefore, err := readSnapshot(managedPath, 16<<20)
	if err != nil {
		return applyResponse{Status: "error", ErrorCode: "dae_config_unavailable"}
	}
	subBefore, err := readSnapshot(subscriptionPath, 10<<20)
	if err != nil {
		return applyResponse{Status: "error", ErrorCode: "dae_config_unavailable"}
	}
	if err := os.MkdirAll(managedDir, 0700); err != nil {
		return applyResponse{Status: "error", ErrorCode: "dae_config_unavailable"}
	}
	// A cached subscription may have been staged by an older helper version.
	// Re-apply the node-name policy before enabling proxy routing so an upgrade
	// cannot leave IPv6-marked nodes in the staged payload.
	if !filterCandidate && request.Policy != nil && request.Policy.ProxyEnabled && subBefore.exists {
		candidate = append([]byte(nil), subBefore.data...)
		filterCandidate = true
	}
	if filterCandidate && len(candidate) != 0 {
		filtered, stats, filterErr := subscription.FilterIPv6NamedPayload(candidate)
		if filterErr != nil {
			log.Printf("IPv6-name subscription filter rejected payload; input=%d kept=%d ipv6_named=%d invalid=%d", stats.Input, stats.Kept, stats.IPv6Named, stats.Invalid)
			return applyResponse{Status: "error", ErrorCode: "subscription_name_filter_failed"}
		}
		candidate = filtered
		log.Printf("IPv6-name subscription filter applied; input=%d kept=%d ipv6_named=%d invalid=%d", stats.Input, stats.Kept, stats.IPv6Named, stats.Invalid)
	}

	configCandidate, changed := ensureInclude(configBefore.data, managedPath)
	hasSubscription := subBefore.exists
	if request.ManageSubscription {
		hasSubscription = directive != nil
	}
	managedCandidate := managedConfig(hasSubscription, false, "")
	if request.Policy != nil {
		policy := *request.Policy
		if policy.DNSBind == "" {
			policy.DNSBind = interfaceIPv4(policy.Interface)
		}
		policy.SubscriptionPresent = hasSubscription
		if len(policy.Rules) > 12000 || len(policy.Nodes) > 10000 || len(policy.DirectHosts) > 32 {
			return applyResponse{Status: "error", ErrorCode: "dae_policy_invalid"}
		}
		var renderErr error
		managedCandidate, renderErr = rules.RenderDaeManaged(policy)
		if renderErr != nil {
			if strings.Contains(renderErr.Error(), "proxy requires a bound subscription") {
				return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_subscription_required"}
			}
			return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_policy_invalid"}
		}
	}
	probeGroup := ""
	// Verify the nodes Dae actually parsed on both a fresh subscription fetch
	// and a local-proxy enable that reuses the root-only cached payload.
	probeRequested := shouldProbeNativeNodeCount(hasSubscription, request)
	if probeRequested {
		probeGroup = nativeCountGroupPrefix + strconv.FormatInt(time.Now().UnixNano(), 10)
		var probeErr error
		managedCandidate, probeErr = insertProbeGroup(managedCandidate, probeGroup)
		if probeErr != nil {
			return applyResponse{Status: "error", ErrorCode: "dae_policy_invalid"}
		}
	}
	if filterCandidate && len(candidate) != 0 {
		if err := atomicWrite(subscriptionPath, candidate, 0600); err != nil {
			return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
		}
	} else if request.ManageSubscription {
		if err := os.Remove(subscriptionPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
		}
	}
	if err := atomicWrite(managedPath, []byte(managedCandidate), 0600); err != nil {
		_ = restore(subscriptionPath, subBefore)
		return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
	}
	configToValidate := configCandidate
	if probeRequested {
		configToValidate, err = setGlobalLogLevel(configCandidate, "debug")
		if err != nil {
			_ = restore(managedPath, managedBefore)
			_ = restore(subscriptionPath, subBefore)
			return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
		}
	}
	if changed || probeRequested {
		if err := atomicWrite(configPath, configToValidate, 0600); err != nil {
			_ = restore(managedPath, managedBefore)
			_ = restore(subscriptionPath, subBefore)
			return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
		}
	}

	rollback := func() {
		_ = restore(configPath, configBefore)
		_ = restore(managedPath, managedBefore)
		_ = restore(subscriptionPath, subBefore)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = run(ctx, "/usr/bin/systemctl", "reload", "dae")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	if _, err := run(ctx, "/usr/bin/dae", "validate", "-c", configPath); err != nil {
		rollback()
		return applyResponse{Status: "error", ErrorCode: "dae_validation_failed"}
	}
	shouldReload := request.ManageSubscription || request.Policy != nil && (request.Policy.ProxyEnabled || strings.Contains(string(managedBefore.data), "# proxy_enabled: true"))
	proxyRequested := request.Policy != nil && request.Policy.ProxyEnabled
	if shouldReload {
		// Offline boot recovery starts dae from the validated cached policy.
		// A subscription inventory refresh while the switch is off may start
		// it temporarily, but must not enable it for the next boot.
		if err := ensureDaeActive(ctx, proxyRequested, proxyRequested || probeRequested, run); err != nil {
			if !proxyRequested && !probeRequested {
				shouldReload = false // inactive direct-only policy: stage it without starting dae
			} else {
				rollback()
				return applyResponse{Status: "error", ErrorCode: "dae_service_inactive"}
			}
		}
	}
	if !shouldReload {
		if changed {
			_ = saveBackup(configBefore)
		}
		token, err := rememberAppliedBackup(configBefore, managedBefore, subBefore)
		if err != nil {
			rollback()
			return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
		}
		return applyResponse{Status: "unchanged", PolicyStatus: "prepared", RollbackToken: token}
	}
	started := time.Now()
	if _, err := run(ctx, "/usr/bin/systemctl", "reload", "dae"); err != nil {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_reload_failed"}
	}
	if !probeRequested {
		if changed {
			_ = saveBackup(configBefore)
		}
		status := "applied"
		if request.ManageSubscription && directive == nil {
			status = "unbound"
		}
		token, err := rememberAppliedBackup(configBefore, managedBefore, subBefore)
		if err != nil {
			rollback()
			return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
		}
		return applyResponse{Status: status, PolicyStatus: status, RollbackToken: token}
	}
	parsedNames, err := awaitDaeNodeNames(ctx, started, probeGroup)
	if err != nil {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_native_count_unavailable"}
	}
	if len(parsedNames) == 0 {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_native_zero_nodes"}
	}
	validatedNodes, err := subscription.ValidatedNodeMetadata(candidate, parsedNames)
	if err != nil {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_node_inventory_invalid"}
	}
	if len(validatedNodes) > 512 {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_node_inventory_invalid"}
	}
	// Dae v2.0.0 exposes parsed dialers in the temporary group's DEBUG list.
	// Remove that probe and its one-shot debug setting before the stable reload.
	stableManaged := managedConfig(true, false, "")
	if request.Policy != nil {
		stablePolicy := *request.Policy
		if stablePolicy.DNSBind == "" {
			stablePolicy.DNSBind = interfaceIPv4(stablePolicy.Interface)
		}
		stablePolicy.SubscriptionPresent = true
		var renderErr error
		stableManaged, renderErr = rules.RenderDaeManaged(stablePolicy)
		if renderErr != nil {
			rollback()
			return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_policy_invalid"}
		}
	}
	if err := atomicWrite(managedPath, []byte(stableManaged), 0600); err != nil {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_config_write_failed"}
	}
	if err := atomicWrite(configPath, configCandidate, 0600); err != nil {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_config_write_failed"}
	}
	if _, err := run(ctx, "/usr/bin/dae", "validate", "-c", configPath); err != nil {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_validation_failed"}
	}
	if _, err := run(ctx, "/usr/bin/systemctl", "reload", "dae"); err != nil {
		rollback()
		return applyResponse{Status: "error", PolicyStatus: "error", ErrorCode: "dae_reload_failed"}
	}
	_ = saveBackup(configBefore)
	log.Printf("dae subscription applied; parsed_nodes=%d", len(validatedNodes))
	token, err := rememberAppliedBackup(configBefore, managedBefore, subBefore)
	if err != nil {
		rollback()
		return applyResponse{Status: "error", ErrorCode: "dae_config_write_failed"}
	}
	return applyResponse{Status: "ok", NodeCount: len(validatedNodes), Nodes: validatedNodes, PolicyStatus: "applied", RollbackToken: token}
}

type daeCommandRunner func(context.Context, string, ...string) ([]byte, error)

func ensureDaeActive(ctx context.Context, persist, allowStart bool, command daeCommandRunner) error {
	if persist {
		if _, err := command(ctx, "/usr/bin/systemctl", "enable", "dae"); err != nil {
			return errors.New("dae could not be enabled for the next boot")
		}
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dae"); err == nil {
		return nil
	}
	if !allowStart {
		return errors.New("dae is inactive and no start was requested")
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "start", "dae"); err != nil {
		return errors.New("dae could not be started")
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "dae"); err != nil {
		return errors.New("dae did not become active")
	}
	return nil
}

func rememberAppliedBackup(config, managed, sub snapshot) (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	lastAppliedBackup.token = hex.EncodeToString(random[:])
	lastAppliedBackup.config, lastAppliedBackup.managed, lastAppliedBackup.sub = config, managed, sub
	return lastAppliedBackup.token, nil
}

func interfaceIPv4(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ipv4 := ip.To4(); ipv4 != nil && !ipv4.IsUnspecified() && !ipv4.IsLoopback() {
			return ipv4.String()
		}
	}
	return ""
}

func shouldProbeNativeNodeCount(hasSubscription bool, request applyRequest) bool {
	return hasSubscription && (request.ManageSubscription && request.Subscription != nil || request.Policy != nil && request.Policy.ProxyEnabled)
}

func managedConfig(hasSubscription, debugCount bool, probeGroup string) string {
	if !hasSubscription {
		return "# Managed by TY Gateway. Do not edit.\n"
	}
	// dae reads the fetched response from a root-only local file, not a URL.
	// This prevents a reusable tokenized URL from appearing in daemon logs.
	config := "# Managed by TY Gateway. Do not edit.\nsubscription {\n  ty_gateway: 'file://ty-gateway/subscription.raw'\n}\n"
	if debugCount {
		// This group is deliberately unreferenced by routing. Dae still builds
		// its dialer set, so its own DEBUG list is an exact parse count without
		// changing the machine's traffic policy.
		config += "group {\n  " + probeGroup + " {\n    filter: subtag(ty_gateway)\n    policy: fixed(0)\n  }\n}\n"
	}
	return config
}

func insertProbeGroup(config, name string) (string, error) {
	if !strings.HasPrefix(name, nativeCountGroupPrefix) || !validSubscriptionID(name) {
		return "", errors.New("invalid native count group")
	}
	index := strings.Index(config, "\nrouting {")
	if index < 0 {
		return "", errors.New("managed routing block is missing")
	}
	block := "\ngroup {\n  " + name + " {\n    filter: subtag(ty_gateway)\n    policy: fixed(0)\n  }\n}\n"
	return config[:index] + block + config[index:], nil
}

func setGlobalLogLevel(config []byte, level string) ([]byte, error) {
	switch level {
	case "error", "warn", "info", "debug", "trace":
	default:
		return nil, errors.New("invalid dae log level")
	}
	lines := strings.SplitAfter(string(config), "\n")
	foundGlobal := false
	for i, raw := range lines {
		content, ending := raw, ""
		if strings.HasSuffix(content, "\r\n") {
			content, ending = strings.TrimSuffix(content, "\r\n"), "\r\n"
		} else if strings.HasSuffix(content, "\n") {
			content, ending = strings.TrimSuffix(content, "\n"), "\n"
		}
		lineNoComment := strings.SplitN(content, "#", 2)[0]
		clean := strings.TrimSpace(lineNoComment)
		if !foundGlobal {
			if clean == "global {" {
				foundGlobal = true
			}
			continue
		}
		if strings.HasPrefix(clean, "log_level") {
			colon := strings.IndexByte(lineNoComment, ':')
			if colon < 0 {
				return nil, errors.New("invalid dae log_level field")
			}
			comment := ""
			if at := strings.IndexByte(content, '#'); at >= 0 {
				comment = " " + content[at:]
			}
			lines[i] = lineNoComment[:colon+1] + " " + level + comment + ending
			return []byte(strings.Join(lines, "")), nil
		}
		if clean == "}" {
			ending := "\n"
			if strings.HasSuffix(raw, "\r\n") {
				ending = "\r\n"
			}
			lines = append(lines[:i], append([]string{"  log_level: " + level + ending}, lines[i:]...)...)
			return []byte(strings.Join(lines, "")), nil
		}
	}
	if foundGlobal {
		return nil, errors.New("unterminated dae global section")
	}
	prefix := "global {\n  log_level: " + level + "\n}\n\n"
	return []byte(prefix + string(config)), nil
}

func validSubscriptionID(id string) bool {
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func ensureInclude(config []byte, includePath string) ([]byte, bool) {
	text := string(config)
	if includeIsActive(text, includePath) {
		return config, false
	}
	lines := strings.SplitAfter(text, "\n")
	offset := 0
	for i, original := range lines {
		active := strings.TrimSpace(strings.SplitN(original, "#", 2)[0])
		if active == "include {" {
			blockEnd := -1
			for j := i + 1; j < len(lines); j++ {
				if strings.TrimSpace(strings.SplitN(lines[j], "#", 2)[0]) == "}" {
					blockEnd = j
					break
				}
			}
			if blockEnd >= 0 {
				insertAt := offset
				for j := i; j < blockEnd; j++ {
					insertAt += len(lines[j])
				}
				return []byte(text[:insertAt] + "  " + includePath + "\n" + text[insertAt:]), true
			}
		}
		offset += len(original)
	}
	return []byte("include {\n  " + includePath + "\n}\n\n" + text), true
}

func includeIsActive(text, includePath string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == includePath {
			return true
		}
	}
	return false
}

func awaitDaeNodeNames(ctx context.Context, since time.Time, probeGroup string) ([]string, error) {
	deadline := time.Now().Add(45 * time.Second)
	last, stableRounds := "", 0
	for time.Now().Before(deadline) {
		// A subscription with many nodes can emit more than 500 lines while
		// dae builds its control plane. Limiting the journal to the last 500
		// lines can drop the temporary group's node-list header and makes a
		// successful parse look like dae_native_count_unavailable. The helper
		// already caps command output in run(); keep the complete post-start
		// slice so the unique probe marker remains discoverable.
		out, err := run(ctx, "/usr/bin/journalctl", "-u", "dae", "--since", "@"+strconv.FormatInt(since.Unix(), 10), "-o", "cat", "--no-pager")
		if err == nil {
			output := string(out)
			if names, ok := parseNativeGroupNodeNames(out, probeGroup); ok {
				fingerprint := strings.Join(names, "\x00")
				if fingerprint == last {
					stableRounds++
				} else {
					last, stableRounds = fingerprint, 0
				}
				// The per-node DEBUG records are emitted synchronously while Dae
				// builds this group. Requiring stable snapshots avoids reading a
				// partially written journal batch without relying on Dae's
				// build-specific reload-finished log text.
				if stableRounds >= 2 {
					return names, nil
				}
			} else {
				last, stableRounds = "", 0
			}
			if strings.Contains(output, "[Reload] Failed") {
				return nil, errors.New("dae reload failed")
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("cancelled")
		case <-time.After(300 * time.Millisecond):
		}
	}
	return nil, errors.New("dae native parse result not observed")
}

func parseNativeGroupNodeCount(logOutput []byte, probeGroup string) (int, bool) {
	names, ok := parseNativeGroupNodeNames(logOutput, probeGroup)
	return len(names), ok
}

func parseNativeGroupNodeNames(logOutput []byte, probeGroup string) ([]string, bool) {
	marker := "Group \"" + probeGroup + "\" node list:"
	lines := strings.Split(string(logOutput), "\n")
	names := []string{}
	found, inList := false, false
	for _, raw := range lines {
		line := strings.TrimLeft(raw, " \t\r")
		if strings.Contains(line, marker) {
			names, found, inList = []string{}, true, true
			continue
		}
		if !found {
			continue
		}
		if strings.Contains(line, "[Reload] Finished") {
			return names, true
		}
		if strings.Contains(line, "[Reload] Failed") {
			return nil, false
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !inList {
			return names, true
		}
		level, message, ok := daeLogMessage(line)
		if !ok || level != "DEBU" && level != "DEBUG" {
			return names, true
		}
		message = strings.TrimSpace(message)
		if message == "<Empty>" {
			return nil, true
		}
		if strings.HasPrefix(message, "Group ") {
			return names, true
		}
		names = append(names, message)
	}
	// A journal snapshot can stop in the middle of a DEBUG list. Never
	// publish a partial dialer inventory merely because the current read hit
	// EOF; wait for the following log record that terminates the list.
	return names, found && !inList
}

func daeLogMessage(line string) (level, message string, ok bool) {
	line = strings.TrimLeft(line, " \t\r\n")
	for _, candidate := range []string{"DEBUG", "DEBU", "INFO", "WARN", "ERRO", "ERROR", "FATA", "PANIC"} {
		if !strings.HasPrefix(line, candidate) {
			continue
		}
		rest := line[len(candidate):]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != '[' {
			continue
		}
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, "[") {
			if end := strings.IndexByte(rest, ']'); end >= 0 {
				rest = strings.TrimLeft(rest[end+1:], " \t")
			}
		}
		return candidate, rest, true
	}
	return "", "", false
}

func run(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cmdCtx, path, args...).Output()
	if len(out) > 1<<20 {
		out = out[:1<<20]
	}
	if err != nil {
		return out, errors.New("managed command failed")
	}
	return out, nil
}

func ensureRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("not a regular file")
	}
	return nil
}

func readSnapshot(path string, maxSize int64) (snapshot, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot{}, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return snapshot{}, errors.New("unsafe configuration path")
	}
	f, err := os.Open(path)
	if err != nil {
		return snapshot{}, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil || int64(len(data)) > maxSize {
		return snapshot{}, errors.New("configuration file too large")
	}
	return snapshot{data: data, exists: true}, nil
}

func restore(path string, before snapshot) error {
	if !before.exists {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return atomicWrite(path, before.data, 0600)
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ty-gateway-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func saveBackup(before snapshot) error {
	if !before.exists {
		return nil
	}
	if _, err := os.Lstat(backupPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicWrite(backupPath, before.data, 0600)
}
