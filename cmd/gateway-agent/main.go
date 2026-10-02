package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/hostnet"
	"tygateway/internal/identity"
	"tygateway/internal/model"
	"tygateway/internal/nodeprobe"
)

const defaultVersion = "0.8.11"

const (
	localProxyFile = "local-proxy.json"
	controlSocket  = "/run/ty-gateway-agent/control.sock"
)

var version = defaultVersion

type credentialState struct {
	Server       string `json:"server"`
	DeviceID     string `json:"device_id"`
	DeviceSecret string `json:"device_secret"`
	Serial       string `json:"serial,omitempty"`
	MAC          string `json:"mac,omitempty"`
	RescuePort   int    `json:"rescue_port,omitempty"`
}

type registerResponse struct {
	Device struct {
		ID     string `json:"id"`
		Serial string `json:"serial"`
	} `json:"device"`
	Credentials struct {
		DeviceID     string `json:"device_id"`
		DeviceSecret string `json:"device_secret"`
	} `json:"credentials"`
	Rescue *model.RescueConfig `json:"rescue,omitempty"`
}

type activationFile struct {
	MAC            string `json:"mac"`
	ActivationCode string `json:"activation_code"`
	DeviceSecret   string `json:"device_secret,omitempty"`
}

type pendingIdentity struct {
	MAC          string `json:"mac"`
	DeviceSecret string `json:"device_secret"`
}

type commandEnvelope struct {
	Commands []model.Command `json:"commands"`
}

type daeApplyResult struct {
	Status        string                  `json:"status"`
	NodeCount     int                     `json:"node_count"`
	Nodes         []model.CustomerNode    `json:"nodes,omitempty"`
	PolicyStatus  string                  `json:"policy_status,omitempty"`
	ErrorCode     string                  `json:"error_code,omitempty"`
	RollbackToken string                  `json:"rollback_token,omitempty"`
	ServiceActive bool                    `json:"service_active"`
	Observations  []nodeprobe.Observation `json:"observations,omitempty"`
}

type daeApplier interface {
	Apply(context.Context, bool, *model.DaeSubscription, *model.DaePolicy) (daeApplyResult, error)
	Stop(context.Context) error
	ServiceActive(context.Context) (bool, error)
}

type unixDaeApplier struct{ socketPath string }

type daeApplyRequest struct {
	ManageSubscription bool                   `json:"manage_subscription"`
	Subscription       *model.DaeSubscription `json:"subscription,omitempty"`
	Policy             *model.DaePolicy       `json:"policy,omitempty"`
	RollbackToken      string                 `json:"rollback_token,omitempty"`
	ServiceAction      string                 `json:"service_action,omitempty"`
	Probe              *nodeprobe.Request     `json:"probe,omitempty"`
}

type agent struct {
	server                   string
	stateDir                 string
	interfaceName            string
	interval                 time.Duration
	configEvery              time.Duration
	ipv4RecheckEvery         time.Duration
	subscriptionRefreshEvery time.Duration
	allowDaeProxy            bool
	client                   *http.Client
	state                    credentialState
	stateMu                  sync.RWMutex
	configMu                 sync.Mutex
	daeApplier               daeApplier
	autoFRP                  *autoFRPManager
	autoFRPState             string
	updateSocket             string
	daeStatus                string
	daeSubID                 string
	daeNodeCount             int
	daePolicyHash            string
	lastConfig               time.Time
	lastIPv4Recheck          time.Time
	lastSubscriptionRefresh  time.Time
	logger                   *log.Logger
	localProxyOn             bool
	proxyApplied             bool
	policyReady              bool
	lastReportedInventory    string
	syncNow                  chan struct{}
	probeMu                  sync.Mutex
	probeRunning             bool
	lastProbeStarted         time.Time
}

type localControlRequest struct {
	Action  string          `json:"action"`
	Enabled *bool           `json:"enabled,omitempty"`
	Method  string          `json:"method,omitempty"`
	Path    string          `json:"path,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

type localControlResponse struct {
	RulesProfile string          `json:"rules_profile,omitempty"`
	RulesVersion string          `json:"rules_version,omitempty"`
	Enabled      bool            `json:"enabled"`
	Applied      bool            `json:"applied"`
	Ready        bool            `json:"ready"`
	Subscription bool            `json:"subscription_available"`
	NodeCount    int             `json:"node_count"`
	DaemonActive bool            `json:"daemon_active"`
	Error        string          `json:"error,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
}

func main() {
	server := flag.String("server", envOr("TY_CLOUD_URL", "https://oec.188811.xyz:8443"), "TY Cloud base URL")
	stateDir := flag.String("state-dir", envOr("TY_AGENT_STATE_DIR", "/var/lib/ty-gateway"), "private agent state directory")
	interfaceName := flag.String("interface", envOr("TY_AGENT_INTERFACE", ""), "network interface used for the device MAC")
	interval := flag.Duration("interval", durationEnv("TY_AGENT_INTERVAL", 30*time.Second), "heartbeat and command polling interval")
	configEvery := flag.Duration("config-every", durationEnv("TY_AGENT_CONFIG_EVERY", 60*time.Second), "minimum configuration refresh interval")
	ipv4RecheckEvery := flag.Duration("ipv4-recheck-every", durationEnv("TY_AGENT_IPV4_RECHECK_EVERY", 30*time.Minute), "subscription name-filter recheck interval (legacy flag name)")
	subscriptionRefreshEvery := flag.Duration("subscription-refresh-every", durationEnv("TY_AGENT_SUBSCRIPTION_REFRESH_EVERY", 6*time.Hour), "full provider subscription refresh interval")
	allowDaeProxy := flag.Bool("allow-dae-proxy", envBool("TY_AGENT_ALLOW_DAE_PROXY", false), "allow cloud proxy requests to enable local dae routing")
	enroll := flag.Bool("enroll", false, "perform one-time local enrollment, then exit")
	autoEnroll := flag.Bool("auto-enroll", envBool("TY_AGENT_AUTO_ENROLL", false), "enroll automatically when no local credentials exist")
	once := flag.Bool("once", false, "run one heartbeat/config/command cycle, then exit")
	flag.Parse()

	if err := validateURL(*server); err != nil {
		fatal("invalid cloud URL: %v", err)
	}
	if *interval <= 0 || *configEvery <= 0 || *ipv4RecheckEvery <= 0 || *subscriptionRefreshEvery <= 0 {
		fatal("intervals must be positive")
	}

	a := &agent{
		server:                   strings.TrimRight(strings.TrimSpace(*server), "/"),
		stateDir:                 filepath.Clean(*stateDir),
		interfaceName:            strings.TrimSpace(*interfaceName),
		interval:                 *interval,
		configEvery:              *configEvery,
		ipv4RecheckEvery:         *ipv4RecheckEvery,
		subscriptionRefreshEvery: *subscriptionRefreshEvery,
		allowDaeProxy:            *allowDaeProxy,
		client:                   &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{MaxIdleConns: 8, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second}},
		daeApplier:               unixDaeApplier{socketPath: envOr("TY_DAE_HELPER_SOCKET", "/run/ty-gateway-dae-helper.sock")},
		autoFRP:                  newAutoFRPManager(filepath.Join(filepath.Clean(*stateDir), "frpc-auto.toml"), envOr("TY_FRPC_BIN", "/usr/local/bin/frpc")),
		updateSocket:             envOr("TY_AGENT_UPDATE_SOCKET", "/run/ty-gateway-update/agent.sock"),
		logger:                   log.New(os.Stderr, "ty-gateway-agent: ", log.LstdFlags),
		syncNow:                  make(chan struct{}, 1),
	}

	if err := os.MkdirAll(a.stateDir, 0700); err != nil {
		fatal("could not create state directory: %v", err)
	}

	if *enroll {
		if err := a.enroll(context.Background()); err != nil {
			fatal("enrollment failed: %v", err)
		}
		a.logger.Printf("enrollment completed; credentials were saved locally")
		return
	}
	if err := a.loadState(); err != nil {
		if !*autoEnroll {
			fatal("agent is not enrolled: %v; run this binary once with --enroll from local console or SSH", err)
		}
		a.logger.Printf("no usable local credentials; starting first enrollment")
		if enrollErr := a.enroll(context.Background()); enrollErr != nil {
			fatal("automatic enrollment failed: %v", enrollErr)
		}
		a.logger.Printf("automatic enrollment completed; credentials were saved locally")
	} else if err := a.cleanupConsumedActivation(); err != nil {
		a.logger.Printf("used activation file could not be removed; cleanup will retry on restart")
	}
	if err := a.reconcileCredentialServer(); err != nil {
		fatal("could not reconcile saved cloud address: %v", err)
	}
	if err := a.loadLocalProxy(); err != nil {
		fatal("could not load local proxy setting")
	}
	// Reconcile the saved local switch before contacting Cloud. This is
	// required both for offline boot (on) and for a daemon left running by
	// an interrupted shutdown (off).
	restoreCtx, cancelRestore := context.WithTimeout(context.Background(), 110*time.Second)
	if err := a.restoreLocalSwitch(restoreCtx); err != nil {
		a.logger.Printf("saved local proxy switch could not yet be restored: %v", err)
	}
	cancelRestore()

	if *once {
		err := a.cycle(context.Background())
		a.reconcileRunningService()
		if err != nil {
			fatal("cycle failed: %v", err)
		}
		return
	}
	go func() {
		if err := a.serveLocalControl(controlSocket); err != nil {
			a.logger.Printf("local proxy control unavailable")
		}
	}()

	a.logger.Printf("started version=%s interval=%s config_refresh=%s subscription_name_recheck=%s subscription_refresh=%s", version, a.interval, a.configEvery, a.ipv4RecheckEvery, a.subscriptionRefreshEvery)
	if err := a.cycle(context.Background()); err != nil {
		a.logger.Printf("initial cycle failed: %v", err)
	}
	a.reconcileRunningService()
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			err := a.cycle(ctx)
			cancel()
			if err != nil {
				a.logger.Printf("cycle failed: %v", err)
			}
			a.reconcileRunningService()
		case <-a.syncNow:
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			err := a.fetchConfig(ctx)
			cancel()
			if err != nil {
				a.logger.Printf("requested config sync failed: %v", safeSyncError(err))
			}
		}
	}
}

func (a *agent) enroll(ctx context.Context) error {
	interfaceName, mac, err := discoverInterface(a.interfaceName)
	if err != nil {
		return err
	}
	a.interfaceName = interfaceName
	return a.enrollWithMAC(ctx, interfaceName, mac)
}

// enrollWithMAC contains the identity-bound enrollment flow after the active
// interface has been discovered. Keeping discovery separate lets the complete
// Cloud claim flow be integration-tested without depending on the test host's
// network interfaces.
func (a *agent) enrollWithMAC(ctx context.Context, interfaceName, mac string) error {
	if strings.TrimSpace(interfaceName) == "" || strings.TrimSpace(mac) == "" {
		return errors.New("device interface identity is unavailable")
	}
	a.interfaceName = interfaceName
	activation, err := a.readActivation(mac)
	if err != nil {
		return err
	}
	deviceSecret := activation.DeviceSecret
	if activation.ActivationCode != "" && activation.DeviceSecret == "" {
		// Persist the new identity before the request. If the Cloud commits but
		// the response is lost, the same code and secret can be retried safely.
		activation.DeviceSecret = identity.NewSecret()
		deviceSecret = activation.DeviceSecret
		data, marshalErr := json.Marshal(activation)
		if marshalErr != nil {
			return marshalErr
		}
		if writeErr := writePrivateFile(filepath.Join(a.stateDir, "activation.json"), data); writeErr != nil {
			return errors.New("activation identity could not be saved")
		}
	}
	if activation.ActivationCode == "" {
		deviceSecret, err = a.loadOrCreatePendingIdentity(mac)
		if err != nil {
			return err
		}
	}
	body, err := json.Marshal(map[string]string{
		"mac":              mac,
		"activation_code":  activation.ActivationCode,
		"device_secret":    deviceSecret,
		"firmware_version": version,
		"agent_version":    version,
		"kernel_version":   kernelVersion(),
		"hardware_version": hardwareVersion(),
		"ip":               localIP(a.interfaceName),
	})
	if err != nil {
		return err
	}
	data, status, err := a.request(ctx, http.MethodPost, "/api/v1/devices/register", body, nil)
	if err != nil {
		return err
	}
	if status == http.StatusConflict {
		return errors.New("device is already registered; existing credentials are never returned by the cloud")
	}
	if status == http.StatusForbidden && activation.ActivationCode == "" {
		return fmt.Errorf("cloud rejected active interface %s MAC %s; verify this exact MAC is pre-registered and not assigned to another device", interfaceName, mac)
	}
	if status != http.StatusCreated {
		return fmt.Errorf("cloud returned HTTP %d", status)
	}
	var out registerResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return fmt.Errorf("invalid enrollment response")
	}
	if out.Device.ID == "" || out.Device.Serial == "" || out.Credentials.DeviceID == "" || out.Credentials.DeviceSecret == "" {
		return errors.New("enrollment response did not contain complete credentials")
	}
	if out.Device.ID != out.Credentials.DeviceID || !strings.EqualFold(out.Device.Serial, mac) || (activation.ActivationCode != "" && out.Credentials.DeviceSecret != activation.DeviceSecret) {
		return errors.New("enrollment response does not match the requested device identity")
	}
	rescuePort := 0
	if out.Rescue != nil {
		rescuePort = out.Rescue.RemotePort
	}
	a.state = credentialState{Server: a.server, DeviceID: out.Credentials.DeviceID, DeviceSecret: out.Credentials.DeviceSecret, Serial: out.Device.Serial, MAC: mac, RescuePort: rescuePort}
	if err := a.saveState(); err != nil {
		return err
	}
	if activation.ActivationCode != "" {
		// The Cloud has consumed this code. The durable credential is now the
		// root-only device secret in credentials.json.
		if err := a.cleanupConsumedActivation(); err != nil {
			a.logger.Printf("used activation file could not be removed; cleanup will retry on restart")
		}
	} else {
		if err := os.Remove(filepath.Join(a.stateDir, "pending-enrollment.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.logger.Printf("pending enrollment identity could not be removed; cleanup will retry on restart")
		}
	}
	return nil
}

func (a *agent) loadOrCreatePendingIdentity(mac string) (string, error) {
	path := filepath.Join(a.stateDir, "pending-enrollment.json")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
			return "", errors.New("pending enrollment identity is not a private regular file")
		}
		data, readErr := os.ReadFile(path)
		var pending pendingIdentity
		if readErr != nil || len(data) > 4096 || json.Unmarshal(data, &pending) != nil || !strings.EqualFold(strings.TrimSpace(pending.MAC), mac) || !validSecret(pending.DeviceSecret) {
			return "", errors.New("pending enrollment identity is invalid or belongs to another MAC")
		}
		return pending.DeviceSecret, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("pending enrollment identity cannot be inspected")
	}
	pending := pendingIdentity{MAC: mac, DeviceSecret: identity.NewSecret()}
	data, err := json.Marshal(pending)
	if err != nil {
		return "", err
	}
	if err := writePrivateFile(path, data); err != nil {
		return "", errors.New("pending enrollment identity could not be saved")
	}
	return pending.DeviceSecret, nil
}

func validSecret(secret string) bool {
	if len(secret) != 64 {
		return false
	}
	for _, r := range secret {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

func (a *agent) cleanupConsumedActivation() error {
	for _, name := range []string{"activation.json", "pending-enrollment.json"} {
		err := os.Remove(filepath.Join(a.stateDir, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (a *agent) readActivation(mac string) (activationFile, error) {
	path := filepath.Join(a.stateDir, "activation.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return activationFile{}, nil // development/legacy Cloud may still allow pending enrollment
	}
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return activationFile{}, errors.New("activation.json is missing or has unsafe permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return activationFile{}, errors.New("activation.json cannot be read")
	}
	var activation activationFile
	if len(data) > 4096 || json.Unmarshal(data, &activation) != nil || len(activation.ActivationCode) != 64 || !strings.EqualFold(strings.TrimSpace(activation.MAC), mac) || (activation.DeviceSecret != "" && len(activation.DeviceSecret) != 64) {
		return activationFile{}, errors.New("activation.json does not match this device")
	}
	return activation, nil
}

func (a *agent) cycle(ctx context.Context) error {
	var failures []error
	if err := a.sendStatus(ctx, "/heartbeat"); err != nil {
		failures = append(failures, fmt.Errorf("heartbeat: %s", safeSyncError(err)))
	}
	if time.Since(a.lastConfig) >= a.configEvery || a.subscriptionRefreshDue() || a.ipv4RecheckDue() {
		fullRefresh := a.subscriptionRefreshDue()
		recheckIPv4 := !fullRefresh && a.ipv4RecheckDue()
		if fullRefresh {
			a.logger.Printf("scheduled subscription refresh started")
		} else if recheckIPv4 {
			a.logger.Printf("scheduled subscription name-filter recheck started")
		}
		if err := a.fetchConfigWithOptions(ctx, fullRefresh, recheckIPv4); err != nil {
			failures = append(failures, fmt.Errorf("config sync: %s", safeSyncError(err)))
		}
	}
	if err := a.pollCommands(ctx); err != nil {
		failures = append(failures, fmt.Errorf("command poll: %s", safeSyncError(err)))
	}
	return errors.Join(failures...)
}

func (a *agent) sendStatus(ctx context.Context, endpoint string) error {
	cpu, memory := hostUsage()
	a.stateMu.RLock()
	daeStatus, daeSubID, daeNodeCount := a.daeStatus, a.daeSubID, a.daeNodeCount
	a.stateMu.RUnlock()
	body, err := json.Marshal(model.DeviceReport{
		FirmwareVersion:   version,
		AgentVersion:      version,
		KernelVersion:     kernelVersion(),
		HardwareVersion:   hardwareVersion(),
		IP:                localIP(a.interfaceName),
		Status:            "ok",
		CPUPercent:        cpu,
		MemoryPercent:     memory,
		DaeStatus:         daeStatus,
		DaeSubscriptionID: daeSubID,
		DaeNodeCount:      daeNodeCount,
	})
	if err != nil {
		return err
	}
	_, status, err := a.signedRequest(ctx, http.MethodPost, "/api/v1/device/"+url.PathEscape(a.stateValue().DeviceID)+endpoint, body)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("status endpoint returned HTTP %d", status)
	}
	return nil
}

func (a *agent) fetchConfig(ctx context.Context) error {
	return a.fetchConfigWithOptions(ctx, false, false)
}

func (a *agent) fetchConfigWithForce(ctx context.Context, forceSubscription bool) error {
	return a.fetchConfigWithOptions(ctx, forceSubscription, false)
}

func (a *agent) fetchConfigWithOptions(ctx context.Context, forceSubscription, recheckIPv4 bool) error {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	return a.fetchConfigLocked(ctx, forceSubscription, recheckIPv4)
}

func (a *agent) fetchConfigLocked(ctx context.Context, forceSubscription, recheckIPv4 bool) error {
	return a.fetchConfigLockedWithReset(ctx, forceSubscription, recheckIPv4, false)
}

func (a *agent) fetchConfigLockedWithReset(ctx context.Context, forceSubscription, recheckIPv4, resetLocalPreferences bool, resetCommandIDs ...string) error {
	started := time.Now()
	data, status, err := a.signedRequest(ctx, http.MethodGet, "/api/v1/device/"+url.PathEscape(a.stateValue().DeviceID)+"/config", nil)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("config endpoint returned HTTP %d", status)
	}
	var config model.DeviceConfig
	if err := json.Unmarshal(data, &config); err != nil || config.Device.ID == "" || config.ServerTime.IsZero() {
		if a.logger != nil {
			a.logger.Printf("config_sync stage=decode result=invalid_configuration")
		}
		return errors.New("cloud returned invalid configuration")
	}
	if state := a.stateValue(); config.Device.ID != state.DeviceID || (state.Serial != "" && !strings.EqualFold(config.Device.Serial, state.Serial)) {
		return errors.New("cloud returned configuration for a different device")
	}
	if a.autoFRP != nil {
		a.reconcileAutoFRP(ctx, config.AutoFRP)
	}
	if config.Rescue != nil {
		if err := a.persistRescuePort(config.Rescue.RemotePort); err != nil {
			a.logger.Printf("rescue port metadata could not be saved; the next config poll will retry")
		}
	}
	cloudCustomer, err := a.fetchCloudCustomerState(ctx, config)
	if err != nil {
		return err
	}
	previous, previousErr := a.loadAppliedSnapshot()
	localPreferences, localRevision := previous.LocalPreferences, previous.LocalRevision
	resetCommandID := previous.LastResetCommandID
	if len(resetCommandIDs) > 0 && resetCommandIDs[0] != "" {
		if resetCommandIDs[0] == previous.LastResetCommandID {
			resetLocalPreferences = false
		}
		resetCommandID = resetCommandIDs[0]
	}
	if resetLocalPreferences && len(localPreferences) > 0 {
		localPreferences = nil
		localRevision++
	}
	boundSubscriptionID := ""
	if config.DaeSubscription != nil {
		boundSubscriptionID = config.DaeSubscription.ID
	}
	validatedNodes := []model.CustomerNode{}
	if previousErr == nil && previous.SubscriptionID == boundSubscriptionID {
		validatedNodes = customerNodes(previous.Config.Nodes)
		config.Nodes = append([]model.Node(nil), previous.Config.Nodes...)
	}
	var applyErr error
	a.stateMu.RLock()
	previousStatus, previousSubID, previousCount := a.daeStatus, a.daeSubID, a.daeNodeCount
	previousApplied, previousReady := a.proxyApplied, a.policyReady
	a.stateMu.RUnlock()
	previousPolicyHash := a.daePolicyHash
	rollbackToken := ""
	failUpdate := func(cause error) error {
		if rollbackToken == "" {
			return cause
		}
		rollbacker, ok := a.daeApplier.(interface {
			Rollback(context.Context, string) error
		})
		if !ok {
			return fmt.Errorf("%w; dae rollback is unavailable", cause)
		}
		rollbackCtx, cancelRollback := context.WithTimeout(context.WithoutCancel(ctx), 35*time.Second)
		err := rollbacker.Rollback(rollbackCtx, rollbackToken)
		cancelRollback()
		if err != nil {
			a.stateMu.Lock()
			a.daeStatus, a.proxyApplied, a.policyReady = "error", false, false
			a.stateMu.Unlock()
			return fmt.Errorf("%w; dae rollback could not be confirmed", cause)
		}
		a.stateMu.Lock()
		a.daeStatus, a.daeSubID, a.daeNodeCount = previousStatus, previousSubID, previousCount
		a.proxyApplied, a.policyReady = previousApplied, previousReady
		a.stateMu.Unlock()
		a.daePolicyHash = previousPolicyHash
		return cause
	}
	subscriptionChanged := config.DaeSubscriptionManaged && a.shouldApplyDaeSubscription(config.DaeSubscription, forceSubscription)
	config = overlayLocalPreferences(config, localPreferences)
	config.Rules = safeCompiledNodeActions(config.Rules, validatedNodes, subscriptionChanged)
	config.BaseRules = safeCompiledNodeActions(config.BaseRules, validatedNodes, subscriptionChanged)
	if !a.allowDaeProxy && config.Device.CustomerOverrideAction == "PROXY" && config.Device.CustomerOverrideUntil != nil && config.Device.CustomerOverrideUntil.After(config.ServerTime) {
		a.logger.Printf("cloud proxy request is staged; local Dae routing safety gate is off")
	}
	policy := makeDaePolicy(a.server, a.interfaceName, config, a.allowDaeProxy)
	policy.TCPCheckURL = a.localCheckTarget()
	if a.allowDaeProxy {
		a.stateMu.RLock()
		localEnabled := a.localProxyOn
		a.stateMu.RUnlock()
		policy.ProxyEnabled = localEnabled && config.DaeSubscriptionManaged && config.DaeSubscription != nil
		policy.Rules = localDaeRules(config, localEnabled)
		if config.Device.CustomerOverrideAction == "DIRECT" && config.Device.CustomerOverrideUntil != nil && config.Device.CustomerOverrideUntil.After(config.ServerTime) {
			policy.ProxyEnabled = false
			policy.Rules = config.Rules
		}
	}
	recheckRequested := recheckIPv4 && !subscriptionChanged && policy.ProxyEnabled && config.DaeSubscriptionManaged && config.DaeSubscription != nil
	policy.RecheckIPv4Only = recheckRequested
	policyForHash := policy
	policyForHash.RecheckIPv4Only = false
	policyJSON, err := json.Marshal(policyForHash)
	if err != nil {
		return errors.New("could not prepare dae policy")
	}
	policyHash := fmt.Sprintf("%x", sha256.Sum256(policyJSON))
	policyChanged := policyHash != a.daePolicyHash
	daeApplied := subscriptionChanged || policyChanged || recheckRequested
	a.stateMu.RLock()
	localProxyEnabled := a.localProxyOn
	a.stateMu.RUnlock()
	if a.allowDaeProxy && localProxyEnabled && (!config.DaeSubscriptionManaged || config.DaeSubscription == nil) {
		applyErr = errors.New("a valid subscription is required to enable proxy routing")
	}
	if daeApplied && config.DaeSubscriptionManaged && applyErr == nil {
		applyCtx, cancelApply := context.WithTimeout(context.WithoutCancel(ctx), 105*time.Second)
		result, err := a.daeApplier.Apply(applyCtx, subscriptionChanged, config.DaeSubscription, &policy)
		cancelApply()
		rollbackToken = result.RollbackToken
		if subscriptionChanged {
			subscriptionApplied := err == nil && ((result.Status == "ok" && result.NodeCount > 0 && len(result.Nodes) == result.NodeCount) || result.Status == "unbound")
			if subscriptionApplied {
				if result.Status == "ok" {
					validatedNodes = append([]model.CustomerNode(nil), result.Nodes...)
				} else {
					validatedNodes = nil
				}
				a.stateMu.Lock()
				if config.DaeSubscription != nil {
					a.daeSubID = config.DaeSubscription.ID
				} else {
					a.daeSubID = ""
				}
				a.daeStatus, a.daeNodeCount = result.Status, result.NodeCount
				a.stateMu.Unlock()
			} else if applyErr == nil {
				// The helper rolls back on fetch/filter/validation failure. Keep
				// reporting the previous last-known-good payload instead of
				// claiming that the device has no usable subscription.
				applyErr = errors.New("dae subscription refresh failed; last-known-good payload retained")
			}
			if subscriptionApplied && result.Status == "ok" {
				a.logger.Printf("dae subscription applied; parsed_nodes=%d", result.NodeCount)
			}
		}
		if policyChanged || recheckRequested {
			if !daePolicyConfirmed(policy.ProxyEnabled, result, err) {
				if applyErr == nil {
					applyErr = errors.New("dae policy apply failed")
				}
			} else if policy.ProxyEnabled && len(result.Nodes) != result.NodeCount {
				applyErr = errors.New("dae did not return a complete validated node inventory")
			} else {
				if policy.ProxyEnabled {
					validatedNodes = append([]model.CustomerNode(nil), result.Nodes...)
				}
				a.daePolicyHash = policyHash
				a.stateMu.Lock()
				a.proxyApplied = policy.ProxyEnabled
				a.policyReady = true
				if policy.ProxyEnabled {
					a.daeStatus = "ok"
					a.daeNodeCount = result.NodeCount
				}
				a.stateMu.Unlock()
				if recheckRequested {
					a.logger.Printf("dae subscription name-filter recheck applied; parsed_nodes=%d", result.NodeCount)
				} else {
					a.logger.Printf("dae policy %s; proxy_enabled=%t", result.PolicyStatus, policy.ProxyEnabled)
				}
			}
		}
		if applyErr != nil {
			// Never log helper output: it must not include provider URLs or payloads.
			if safeDaeErrorCode(result.ErrorCode) {
				a.logger.Printf("dae configuration apply failed; code=%s", result.ErrorCode)
			} else {
				a.logger.Printf("dae configuration apply failed")
			}
		}
	}
	subscriptionRefreshAttempted := subscriptionChanged && config.DaeSubscription != nil
	if applyErr != nil {
		if subscriptionRefreshAttempted {
			a.lastSubscriptionRefresh = time.Now()
		}
		if recheckIPv4 {
			a.lastIPv4Recheck = time.Now()
		}
		return failUpdate(applyErr) // Never replace a last-known-good snapshot after a failed apply.
	}
	if config.DaeSubscriptionManaged && boundSubscriptionID != "" && len(validatedNodes) == 0 {
		return failUpdate(errors.New("dae validated node inventory is unavailable"))
	}
	config.Nodes, err = safePolicyNodes(validatedNodes)
	if err != nil {
		return failUpdate(err)
	}
	cloudCustomer, err = stateWithValidatedNodes(cloudCustomer, validatedNodes)
	if err != nil {
		return failUpdate(err)
	}
	cloudCustomer, err = stateWithLocalPreferences(cloudCustomer, config.Preferences, localRevision)
	if err != nil {
		return failUpdate(err)
	}
	if err := a.saveSnapshotWithPreferences(config, cloudCustomer, boundSubscriptionID, localPreferences, localRevision, resetCommandID); err != nil {
		if a.logger != nil {
			a.logger.Printf("config_sync stage=snapshot result=write_failed")
		}
		return failUpdate(fmt.Errorf("save applied configuration: %w", err))
	}
	a.lastConfig = time.Now()
	if a.logger != nil {
		a.logger.Printf("config_sync stage=applied version=%d elapsed_ms=%d", config.ConfigVersion, time.Since(started).Milliseconds())
	}
	if subscriptionRefreshAttempted {
		a.lastSubscriptionRefresh = a.lastConfig
		a.lastIPv4Recheck = a.lastConfig
	}
	if recheckIPv4 {
		// A failed recheck leaves the last-known-good dae payload in place; mark
		// the attempt time anyway so a transient apply failure cannot cause a
		// one-minute retry storm.
		a.lastIPv4Recheck = a.lastConfig
	}
	if daeApplied {
		// A native dae reload may outlive one normal polling interval. Report its
		// final state promptly with a short bounded status request even if the
		// original polling context has expired while dae was rebuilding.
		statusCtx, cancelStatus := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
		if err := a.sendStatus(statusCtx, "/heartbeat"); err != nil {
			a.logger.Printf("could not report dae status")
		}
		cancelStatus()
	}
	if len(validatedNodes) > 0 && boundSubscriptionID != "" {
		inventory := nodeIdentities(validatedNodes)
		inventoryJSON, _ := json.Marshal(inventory)
		inventoryHash := fmt.Sprintf("%x", sha256.Sum256(append([]byte(boundSubscriptionID), inventoryJSON...)))
		if inventoryHash != a.lastReportedInventory {
			reportCtx, cancelReport := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			if err := a.reportValidatedNodes(reportCtx, boundSubscriptionID, inventory); err != nil {
				a.logger.Printf("validated node inventory is local; cloud metadata sync will retry")
			} else {
				a.lastReportedInventory = inventoryHash
			}
			cancelReport()
		}
	}
	return nil
}

func (a *agent) reconcileAutoFRP(ctx context.Context, config *model.AutoFRPConfig) {
	if a.autoFRP == nil {
		return
	}
	if err := a.autoFRP.Apply(ctx, a.stateValue(), config); err != nil {
		// FRPC verifier output may contain generated configuration fields. Never
		// copy it into the journal, where device-derived credentials could leak.
		a.autoFRPState = "apply-failed"
		if a.logger != nil {
			a.logger.Printf("automatic FRP reconciliation deferred")
		}
		return
	}
	if config == nil {
		if a.autoFRPState != "cloud-config-absent" && a.logger != nil {
			a.logger.Printf("automatic FRP config absent from Cloud; client stopped while waiting for per-device authorization")
		}
		a.autoFRPState = "cloud-config-absent"
		return
	}
	encoded, _ := json.Marshal(config)
	configKey := fmt.Sprintf("configured:%x", sha256.Sum256(encoded))
	if a.autoFRPState != configKey && a.logger != nil {
		a.logger.Printf("automatic FRP client process started; tunnel reachability remains unverified; control_port=%d remote_port=%d", config.ControlPort, config.RemotePort)
	}
	a.autoFRPState = configKey
}

func (a *agent) subscriptionRefreshDue() bool {
	if a.subscriptionRefreshEvery <= 0 {
		return false
	}
	a.stateMu.RLock()
	enabled := a.localProxyOn && a.daeSubID != ""
	a.stateMu.RUnlock()
	return enabled && (a.lastSubscriptionRefresh.IsZero() || time.Since(a.lastSubscriptionRefresh) >= a.subscriptionRefreshEvery)
}

func (a *agent) ipv4RecheckDue() bool {
	if a.ipv4RecheckEvery <= 0 {
		return false
	}
	a.stateMu.RLock()
	enabled := a.localProxyOn && a.daeSubID != ""
	a.stateMu.RUnlock()
	return enabled && (a.lastIPv4Recheck.IsZero() || time.Since(a.lastIPv4Recheck) >= a.ipv4RecheckEvery)
}

func (a *agent) localProxyPath() string {
	return filepath.Join(a.stateDir, localProxyFile)
}

func (a *agent) loadLocalProxy() error {
	data, err := os.ReadFile(a.localProxyPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var value struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	a.localProxyOn = value.Enabled
	return nil
}

func (a *agent) saveLocalProxy(enabled bool) error {
	data, err := json.Marshal(struct {
		Enabled bool `json:"enabled"`
	}{Enabled: enabled})
	if err != nil {
		return err
	}
	return writePrivateFile(a.localProxyPath(), data)
}

func (a *agent) restoreLocalSwitch(ctx context.Context) error {
	if !a.localProxyOn || !a.allowDaeProxy {
		if err := a.daeApplier.Stop(ctx); err != nil {
			return errors.New("dae could not be stopped for the saved off switch")
		}
		return nil
	}
	if state := a.applyCachedPolicy(ctx, true); state.Error != "" {
		return errors.New("last-known-good proxy policy could not be restored")
	}
	return nil
}

func (a *agent) reconcileRunningService() {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	active, err := a.daeApplier.ServiceActive(ctx)
	if err != nil {
		a.logger.Print("dae service state could not be checked")
		return
	}
	a.stateMu.RLock()
	enabled := a.localProxyOn
	ready := a.policyReady
	a.stateMu.RUnlock()
	if !enabled && active {
		if err := a.daeApplier.Stop(ctx); err != nil {
			a.logger.Print("dae remained active while local proxy switch was off")
		}
	} else if enabled && (!active || !ready) && a.allowDaeProxy {
		if state := a.applyCachedPolicy(ctx, true); state.Error != "" {
			a.logger.Print("dae could not be restored from the cached policy")
		}
	}
}

func (a *agent) localControlStatus() localControlResponse {
	var applied struct {
		Profile string `json:"rules_profile"`
		Version string `json:"rules_version"`
	}
	if snapshot, err := a.loadAppliedSnapshot(); err == nil {
		applied.Profile, applied.Version = snapshot.Config.Profile, snapshot.Config.RulePackageVersion
	} else {
		if data, e := os.ReadFile(filepath.Join(a.stateDir, "applied-rules.json")); e == nil {
			_ = json.Unmarshal(data, &applied)
		}
	}
	a.stateMu.RLock()
	state := localControlResponse{
		RulesProfile: applied.Profile, RulesVersion: applied.Version,
		Enabled:      a.localProxyOn,
		Applied:      a.proxyApplied,
		Ready:        a.policyReady,
		Subscription: a.daeStatus == "ok" && a.daeNodeCount > 0,
		NodeCount:    a.daeNodeCount,
	}
	a.stateMu.RUnlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	active, err := a.daeApplier.ServiceActive(ctx)
	if err != nil {
		state.Applied = false
		state.Error = "无法核实 dae 是否运行，暂不宣称代理已生效。"
		return state
	}
	state.DaemonActive = active
	state.Applied = state.Applied && active
	if !state.Enabled && active {
		state.Error = "开关已关闭，但 dae 仍在运行；正在重试停止服务。"
	}
	return state
}

func (a *agent) setLocalProxy(ctx context.Context, enabled bool) localControlResponse {
	a.configMu.Lock()
	defer a.configMu.Unlock()
	if !enabled {
		if err := a.saveLocalProxy(false); err != nil {
			state := a.localControlStatus()
			state.Error = "无法保存关闭状态；请勿让客户端暂时通过 OEC 网关上网。"
			return state
		}
		a.stateMu.Lock()
		a.localProxyOn = false
		a.stateMu.Unlock()
		if err := a.daeApplier.Stop(ctx); err != nil {
			state := a.localControlStatus()
			state.Error = "关闭状态已保存，但 dae 停止失败；系统会继续重试，请勿让客户端暂时通过 OEC 网关上网。"
			return state
		}
		a.stateMu.Lock()
		a.proxyApplied = false
		a.policyReady = true
		a.stateMu.Unlock()
		state := a.applyCachedPolicy(ctx, false)
		if state.Error != "" {
			state = a.localControlStatus()
			state.Error = "dae 已停止并保持关闭；本机直连配置尚未更新。"
		}
		return state
	}
	if !a.allowDaeProxy {
		return a.rejectLocalProxyEnable(ctx, "本机代理安全开关未授权，未启用 dae 代理。")
	}
	a.stateMu.Lock()
	a.localProxyOn = true // Keep the persisted setting off until Dae confirms the live policy.
	a.stateMu.Unlock()
	cloudErr := a.fetchConfigLocked(ctx, false, false)
	var state localControlResponse
	if cloudErr != nil {
		cached := a.applyCachedPolicy(ctx, true)
		if cached.Error != "" {
			return a.rejectLocalProxyEnable(ctx, "云端同步失败，且本机缓存策略未能通过 dae 校验："+cached.Error)
		}
		state = cached
		state.Error = "云端暂不可用，已验证并应用本机最近一次配置；联网恢复后会自动更新。"
	} else {
		state = a.localControlStatus()
	}
	if !state.Applied || !state.Ready || !state.Subscription || state.NodeCount <= 0 {
		return a.rejectLocalProxyEnable(ctx, "dae 未确认订阅节点和代理策略均已生效，代理保持关闭。")
	}
	if err := a.saveLocalProxy(true); err != nil {
		return a.rejectLocalProxyEnable(ctx, "dae 已应用策略，但本地开关状态无法安全保存；正在恢复直连。")
	}
	return state
}

func (a *agent) rejectLocalProxyEnable(ctx context.Context, reason string) localControlResponse {
	persistErr := a.saveLocalProxy(false)
	a.stateMu.Lock()
	a.localProxyOn = false
	a.daePolicyHash = ""
	a.stateMu.Unlock()
	state := a.applyCachedPolicy(ctx, false)
	if state.Error != "" {
		// A first-time enable has no last-known-good snapshot yet. Still ask
		// the privileged helper for a minimal direct policy so failure cannot
		// leave a partially applied proxy policy active.
		a.stateMu.RLock()
		hasSubscription := a.daeSubID != ""
		a.stateMu.RUnlock()
		directCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		result, err := a.daeApplier.Apply(directCtx, false, nil, &model.DaePolicy{Profile: "gfw_precise", Interface: a.interfaceName, SubscriptionPresent: hasSubscription})
		cancel()
		if daePolicyConfirmed(false, result, err) {
			a.stateMu.Lock()
			a.proxyApplied = false
			a.policyReady = true
			a.stateMu.Unlock()
			state = a.localControlStatus()
		}
	}
	stopErr := a.daeApplier.Stop(ctx)
	if stopErr == nil {
		a.stateMu.Lock()
		a.proxyApplied = false
		a.stateMu.Unlock()
		state = a.localControlStatus()
	}
	if stopErr != nil {
		state.Error = reason + "且 dae 停止失败；请勿让客户端暂时通过 OEC 网关上网。"
	} else if persistErr != nil {
		state.Error = reason + "关闭状态保存失败；请勿让客户端暂时通过 OEC 网关上网。"
	} else if state.Error != "" {
		state.Error = reason + "并且未能确认 dae 已恢复直连；请勿让客户端暂时通过 OEC 网关上网。"
	} else {
		state.Error = reason + "已恢复直连，开关保持关闭。"
	}
	return state
}

func (a *agent) applyCachedPolicy(ctx context.Context, enabled bool) localControlResponse {
	snapshot, err := a.loadAppliedSnapshot()
	var config model.DeviceConfig
	if err == nil {
		config = snapshot.Config
	} else {
		if enabled {
			state := a.localControlStatus()
			state.Error = "本机没有已验证的节点与规则快照，不能离线开启代理。"
			return state
		}
		// Existing installations may still have the previous private cache. It
		// is used only for recovery until the first validated snapshot is saved.
		data, legacyErr := os.ReadFile(filepath.Join(a.stateDir, "config.json"))
		if legacyErr == nil {
			legacyErr = json.Unmarshal(data, &config)
		}
		if legacyErr != nil {
			state := a.localControlStatus()
			state.Error = "找不到本机最近一次同步的配置，dae 尚未确认切换。"
			return state
		}
	}
	if config.Profile == "" {
		state := a.localControlStatus()
		state.Error = "本机最近一次同步的配置无法读取，dae 尚未确认切换。"
		return state
	}
	if enabled && (!config.DaeSubscriptionManaged || snapshot.SubscriptionID == "") {
		state := a.localControlStatus()
		state.Error = "设备尚未绑定可用订阅，请先在管理端绑定并同步订阅。"
		return state
	}
	policy := makeDaePolicy(a.server, a.interfaceName, config, false)
	policy.TCPCheckURL = a.localCheckTarget()
	policy.Rules = localDaeRules(config, enabled)
	policy.SubscriptionPresent = snapshot.SubscriptionID != ""
	policy.ProxyEnabled = enabled && snapshot.SubscriptionID != ""
	if enabled && config.Device.CustomerOverrideAction == "DIRECT" && config.Device.CustomerOverrideUntil != nil && config.Device.CustomerOverrideUntil.After(time.Now().UTC()) {
		policy.ProxyEnabled = false
	}
	result, err := a.daeApplier.Apply(ctx, false, nil, &policy)
	if !daePolicyConfirmed(policy.ProxyEnabled, result, err) {
		state := a.localControlStatus()
		state.Error = "dae 未确认应用最近一次配置，请稍后重试并检查运行状态。"
		return state
	}
	policyJSON, _ := json.Marshal(policy)
	policyHash := fmt.Sprintf("%x", sha256.Sum256(policyJSON))
	a.stateMu.Lock()
	a.proxyApplied = policy.ProxyEnabled
	a.policyReady = true
	a.daePolicyHash = policyHash
	if policy.ProxyEnabled {
		a.daeStatus = "ok"
		a.daeNodeCount = result.NodeCount
		a.daeSubID = snapshot.SubscriptionID
	}
	a.stateMu.Unlock()
	return a.localControlStatus()
}

func daePolicyConfirmed(proxyEnabled bool, result daeApplyResult, err error) bool {
	if err != nil {
		return false
	}
	if proxyEnabled {
		return result.Status == "ok" && result.PolicyStatus == "applied" && result.NodeCount > 0
	}
	return result.Status != "error" && (result.PolicyStatus == "prepared" || result.PolicyStatus == "applied" || result.PolicyStatus == "unbound")
}

func (a *agent) serveLocalControl(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(path) }()
	group, err := user.LookupGroup("typroxy")
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || os.Chmod(path, 0660) != nil || os.Chown(path, -1, gid) != nil {
		return errors.New("could not secure local control socket")
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go a.serveLocalControlConn(conn)
	}
}

func (a *agent) serveLocalControlConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(125 * time.Second))
	var request localControlRequest
	if err := json.NewDecoder(io.LimitReader(conn, 384<<10)).Decode(&request); err != nil {
		_ = json.NewEncoder(conn).Encode(localControlResponse{Error: "本地控制请求无效。"})
		return
	}
	switch request.Action {
	case "status":
		_ = json.NewEncoder(conn).Encode(a.localControlStatus())
	case "set":
		if request.Enabled == nil {
			_ = json.NewEncoder(conn).Encode(localControlResponse{Error: "缺少开关状态。"})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		_ = json.NewEncoder(conn).Encode(a.setLocalProxy(ctx, *request.Enabled))
	case "customer":
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		_ = json.NewEncoder(conn).Encode(a.localCustomerRequest(ctx, request))
	default:
		_ = json.NewEncoder(conn).Encode(localControlResponse{Error: "本地控制操作无效。"})
	}
}

func (a *agent) localCustomerRequest(ctx context.Context, request localControlRequest) localControlResponse {
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	path := strings.TrimSpace(request.Path)
	if path == "/speed-test" || path == "/speed-test/settings" || path == "/speed-test/run" {
		return a.localNodeProbe(ctx, method, path, request.Body)
	}
	if method == http.MethodPost && path == "/node-preference" {
		return a.saveLocalNodePreference(ctx, request.Body)
	}
	allowed := map[string]bool{
		"POST /rule-package":    true,
		"GET /me":               true,
		"GET /rules":            true,
		"POST /rules":           true,
		"POST /rules/delete":    true,
		"POST /override":        true,
		"POST /node-preference": true,
		"POST /action":          true,
		"POST /settings":        true,
	}
	if !allowed[method+" "+path] || !strings.HasPrefix(path, "/") {
		return localControlResponse{Error: "本地客户操作不受支持。"}
	}
	if method == http.MethodGet && (path == "/me" || path == "/rules") {
		snapshot, err := a.loadAppliedSnapshot()
		if err != nil {
			return localControlResponse{Error: "本机尚无已验证的规则和节点，请先完成同步。"}
		}
		if path == "/me" {
			return localControlResponse{Data: snapshot.Customer}
		}
		var state struct {
			Rules json.RawMessage `json:"rules"`
		}
		if json.Unmarshal(snapshot.Customer, &state) != nil {
			return localControlResponse{Error: "本机规则缓存无效。"}
		}
		data, _ := json.Marshal(map[string]json.RawMessage{"rules": state.Rules})
		return localControlResponse{Data: data}
	}
	state := a.stateValue()
	if state.DeviceID == "" || state.DeviceSecret == "" {
		return localControlResponse{Error: "设备尚未完成云端注册。"}
	}
	body := []byte(request.Body)
	if len(body) > 256<<10 {
		return localControlResponse{Error: "客户配置请求过大。"}
	}
	if body == nil {
		body = []byte{}
	}
	endpoint := "/api/v1/device/" + url.PathEscape(state.DeviceID) + "/customer" + path
	data, status, err := a.signedRequest(ctx, method, endpoint, body)
	if err != nil {
		if safeSyncError(err) == "timeout" {
			return localControlResponse{Error: "连接云端超时，未确认保存；本机保留上次已应用配置，请检查设备 DNS/网络后重试。"}
		}
		return localControlResponse{Error: "设备暂时无法连接云端，未确认保存；本机保留上次已应用配置。"}
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &apiErr) == nil && safeCustomerError(apiErr.Error) {
			return localControlResponse{Error: apiErr.Error}
		}
		return localControlResponse{Error: "云端客户配置暂不可用，请稍后重试。"}
	}
	if len(data) > 256<<10 || !json.Valid(data) {
		return localControlResponse{Error: "云端客户配置响应无效。"}
	}
	if method == http.MethodPost && path != "/action" {
		a.configMu.Lock()
		err := a.fetchConfigLockedWithReset(ctx, false, false, path == "/settings")
		a.configMu.Unlock()
		if err != nil {
			return localControlResponse{Error: "云端已保存，但设备未确认应用；本地记录仍保留上一版，请核对设备状态后重试。"}
		}
	}
	return localControlResponse{Data: json.RawMessage(data)}
}

func safeCustomerError(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 256 || strings.ContainsAny(value, "\r\n") {
		return false
	}
	return true
}

func safeDaeErrorCode(code string) bool {
	switch code {
	case "invalid_request", "dae_config_missing", "invalid_subscription", "subscription_fetch_failed", "subscription_ipv4_filter_failed", "subscription_name_filter_failed",
		"dae_config_unavailable", "dae_config_write_failed", "dae_validation_failed",
		"dae_service_inactive", "dae_reload_failed", "dae_native_count_unavailable",
		"dae_native_zero_nodes", "dae_policy_invalid", "dae_policy_staged",
		"dae_policy_reload_failed", "dae_subscription_required", "dae_probe_restore_failed":
		return true
	default:
		return false
	}
}

func (a *agent) shouldApplyDaeSubscription(directive *model.DaeSubscription, force bool) bool {
	if force {
		return true
	}
	wantedID := ""
	if directive != nil {
		wantedID = directive.ID
	}
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.daeStatus == "" || a.daeStatus == "error" || a.daeSubID != wantedID
}

func makeDaePolicy(server, interfaceName string, config model.DeviceConfig, allowProxy bool) model.DaePolicy {
	policy := model.DaePolicy{
		RulePackageVersion:  config.RulePackageVersion,
		Profile:             config.Profile,
		ProxyEnabled:        allowProxy && config.Device.CustomerOverrideAction == "PROXY" && config.Device.CustomerOverrideUntil != nil && config.Device.CustomerOverrideUntil.After(config.ServerTime),
		Interface:           interfaceName,
		DNSBind:             localIP(interfaceName),
		SubscriptionPresent: config.DaeSubscriptionManaged && config.DaeSubscription != nil,
		Rules:               append([]model.CompiledRule(nil), config.Rules...),
		Nodes:               append([]model.Node(nil), config.Nodes...),
	}
	if !policy.SubscriptionPresent {
		policy.ProxyEnabled = false
	}
	if !allowProxy && config.Device.CustomerOverrideAction == "PROXY" && config.Device.CustomerOverrideUntil != nil && config.Device.CustomerOverrideUntil.After(config.ServerTime) {
		// Deployments can keep cloud-configured proxy controls safely staged
		// until an operator explicitly enables the local Dae routing gate.
		policy.ProxyEnabled = false
	}
	if parsed, err := url.Parse(server); err == nil && parsed.Hostname() != "" {
		policy.DirectHosts = append(policy.DirectHosts, parsed.Hostname())
	}
	if config.Rescue != nil && config.Rescue.Host != "" {
		policy.DirectHosts = append(policy.DirectHosts, config.Rescue.Host)
	}
	if config.AutoFRP != nil && config.AutoFRP.Host != "" && (config.Rescue == nil || config.AutoFRP.Host != config.Rescue.Host) {
		policy.DirectHosts = append(policy.DirectHosts, config.AutoFRP.Host)
	}
	return policy
}

func localDaeRules(config model.DeviceConfig, enabled bool) []model.CompiledRule {
	if enabled && config.Device.CustomerOverrideAction != "DIRECT" && len(config.BaseRules) > 0 {
		return append([]model.CompiledRule(nil), config.BaseRules...)
	}
	return append([]model.CompiledRule(nil), config.Rules...)
}

func (a unixDaeApplier) Apply(ctx context.Context, manageSubscription bool, directive *model.DaeSubscription, policy *model.DaePolicy) (daeApplyResult, error) {
	return a.request(ctx, daeApplyRequest{ManageSubscription: manageSubscription, Subscription: directive, Policy: policy})
}

func (a unixDaeApplier) Rollback(ctx context.Context, token string) error {
	result, err := a.request(ctx, daeApplyRequest{RollbackToken: token})
	if err != nil || result.Status != "reverted" {
		return errors.New("dae rollback failed")
	}
	return nil
}

func (a unixDaeApplier) Stop(ctx context.Context) error {
	result, err := a.request(ctx, daeApplyRequest{ServiceAction: "stop"})
	if err != nil || result.Status != "stopped" {
		return errors.New("dae could not be stopped")
	}
	return nil
}

func (a unixDaeApplier) ServiceActive(ctx context.Context) (bool, error) {
	result, err := a.request(ctx, daeApplyRequest{ServiceAction: "status"})
	if err != nil || result.Status != "ok" {
		return false, errors.New("dae service status unavailable")
	}
	return result.ServiceActive, nil
}

func (a unixDaeApplier) request(ctx context.Context, request daeApplyRequest) (daeApplyResult, error) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", a.socketPath)
	if err != nil {
		return daeApplyResult{}, errors.New("dae helper unavailable")
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return daeApplyResult{}, errors.New("dae helper request failed")
	}
	var result daeApplyResult
	if err := json.NewDecoder(io.LimitReader(conn, 256<<10)).Decode(&result); err != nil {
		return daeApplyResult{}, errors.New("dae helper response invalid")
	}
	return result, nil
}

func (a *agent) pollCommands(ctx context.Context) error {
	data, status, err := a.signedRequest(ctx, http.MethodGet, "/api/v1/device/"+url.PathEscape(a.stateValue().DeviceID)+"/commands", nil)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return fmt.Errorf("command endpoint returned HTTP %d", status)
	}
	var envelope commandEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return errors.New("cloud returned invalid command response")
	}
	commandCtx, cancelCommands := context.WithTimeout(context.WithoutCancel(ctx), 130*time.Second)
	defer cancelCommands()
	for _, command := range envelope.Commands {
		result := "failed"
		switch command.Command {
		case "reload_config":
			var reset struct {
				ResetLocalPreferences bool `json:"reset_local_preferences"`
			}
			if command.Payload != "" {
				_ = json.Unmarshal([]byte(command.Payload), &reset)
			}
			a.configMu.Lock()
			resetID := ""
			if reset.ResetLocalPreferences {
				resetID = command.ID
			}
			err := a.fetchConfigLockedWithReset(commandCtx, false, false, reset.ResetLocalPreferences, resetID)
			a.configMu.Unlock()
			if err == nil {
				result = "ok"
			}
		case "refresh_subscription":
			if err := a.fetchConfigWithForce(commandCtx, true); err == nil {
				result = "ok"
			}
		case "report_status":
			if err := a.sendStatus(commandCtx, "/status"); err == nil {
				result = "ok"
			}
		case "software_update", "software_rollback":
			state, softwareErr := a.remoteSoftwareCommand(commandCtx, command)
			if softwareErr != nil {
				return softwareErr // keep claimed command for retry; never report success before installation
			}
			if state == "running" {
				continue // the Agent may restart during installation; reconcile after restart
			}
			if state == "succeeded" {
				result = "ok"
			}
		default:
			// Never execute arbitrary command names or payloads received from the cloud.
		}
		ackBody, _ := json.Marshal(map[string]string{"status": result})
		_, ackStatus, ackErr := a.signedRequest(commandCtx, http.MethodPost, "/api/v1/device/"+url.PathEscape(a.stateValue().DeviceID)+"/commands/"+url.PathEscape(command.ID)+"/ack", ackBody)
		if ackErr != nil {
			return ackErr
		}
		if ackStatus/100 != 2 {
			return fmt.Errorf("command acknowledgement returned HTTP %d", ackStatus)
		}
	}
	return nil
}

func (a *agent) signedRequest(ctx context.Context, method, path string, body []byte) ([]byte, int, error) {
	state := a.stateValue()
	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%d-%d", timestamp, time.Now().UnixNano())
	key := auth.SecretHash(state.DeviceSecret)
	signature := auth.Sign(method, path, body, timestamp, nonce, key)
	return a.request(ctx, method, path, body, map[string]string{
		"X-TY-Device":    state.DeviceID,
		"X-TY-Timestamp": strconv.FormatInt(timestamp, 10),
		"X-TY-Nonce":     nonce,
		"X-TY-Signature": signature,
	})
}

func cloudRequestStage(method, path string) string {
	switch {
	case strings.HasSuffix(path, "/heartbeat"):
		return "heartbeat"
	case strings.HasSuffix(path, "/status"):
		return "status"
	case strings.HasSuffix(path, "/config"):
		return "config"
	case strings.HasSuffix(path, "/customer/me"):
		return "customer_state"
	case strings.HasSuffix(path, "/customer/node-preference"):
		return "node_preference"
	case strings.HasSuffix(path, "/commands"):
		return "commands"
	case strings.Contains(path, "/commands/"):
		return "command_ack"
	case strings.HasSuffix(path, "/nodes"):
		return "node_inventory"
	default:
		return "other"
	}
}

func safeSyncError(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "failed"
}

func (a *agent) logCloudFailure(method, path, phase string, status int, err error, started time.Time) {
	if a.logger == nil {
		return
	}
	a.logger.Printf("cloud_request stage=%s phase=%s result=%s http_status=%d elapsed_ms=%d",
		cloudRequestStage(method, path), phase, safeSyncError(err), status, time.Since(started).Milliseconds())
}

func (a *agent) request(ctx context.Context, method, path string, body []byte, headers ...map[string]string) ([]byte, int, error) {
	started := time.Now()
	target := a.server + path
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		a.logCloudFailure(method, path, "prepare", 0, err, started)
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, set := range headers {
		for name, value := range set {
			req.Header.Set(name, value)
		}
	}
	resp, err := a.client.Do(req)
	if err != nil {
		a.logCloudFailure(method, path, "request", 0, err, started)
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
	if len(data) > 16<<20 {
		a.logCloudFailure(method, path, "body_size", resp.StatusCode, errors.New("response too large"), started)
		return nil, resp.StatusCode, errors.New("cloud response exceeds limit")
	}
	if err != nil {
		a.logCloudFailure(method, path, "read_body", resp.StatusCode, err, started)
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode/100 != 2 {
		a.logCloudFailure(method, path, "http_status", resp.StatusCode, nil, started)
	}
	return data, resp.StatusCode, nil
}

func (a *agent) loadState() error {
	path := filepath.Join(a.stateDir, "credentials.json")
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("credentials.json is missing")
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return errors.New("credentials.json is not a private regular file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return errors.New("credentials.json cannot be read")
	}
	var state credentialState
	if err := json.Unmarshal(b, &state); err != nil || state.DeviceID == "" || state.DeviceSecret == "" {
		return errors.New("credentials.json is invalid")
	}
	a.stateMu.Lock()
	a.state = state
	a.stateMu.Unlock()
	if a.interfaceName == "" && state.MAC != "" {
		if name, _, err := discoverInterfaceByMAC(state.MAC); err == nil {
			a.interfaceName = name
		}
	}
	return nil
}

func (a *agent) saveState() error {
	a.stateMu.RLock()
	b, err := json.MarshalIndent(a.state, "", "  ")
	a.stateMu.RUnlock()
	if err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(a.stateDir, "credentials.json"), b)
}

// The stock HTTPS endpoint moved ports on the same operator-controlled host.
// Only this exact one-way migration is permitted: an arbitrary server change
// must never transfer existing device credentials to a different destination.
func (a *agent) reconcileCredentialServer() error {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.Server == a.server {
		return nil
	}
	if a.state.Server != "https://oec.188811.xyz" || a.server != "https://oec.188811.xyz:8443" {
		return errors.New("saved credentials belong to a different cloud server")
	}
	next := a.state
	next.Server = a.server
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(a.stateDir, "credentials.json"), data); err != nil {
		return errors.New("could not persist stock HTTPS port migration")
	}
	a.state = next
	if a.logger != nil {
		a.logger.Print("stock device HTTPS port migrated to 8443; device identity unchanged")
	}
	return nil
}

func (a *agent) persistRescuePort(port int) error {
	if port < 0 || port > 65535 {
		return errors.New("invalid rescue port")
	}
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	if a.state.RescuePort == port {
		return nil
	}
	next := a.state
	next.RescuePort = port
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(a.stateDir, "credentials.json"), b); err != nil {
		return err
	}
	a.state = next
	return nil
}

func (a *agent) stateValue() credentialState {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.state
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ty-agent-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func discoverInterface(preferred string) (string, string, error) {
	if preferred != "" {
		mac, err := interfaceMAC(preferred)
		return preferred, mac, err
	}
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", "", fmt.Errorf("cannot inspect network interfaces")
	}
	if defaultIface, _ := hostnet.DefaultRoute(); defaultIface != "" {
		if mac, macErr := interfaceMAC(defaultIface); macErr == nil {
			return defaultIface, mac, nil
		}
	}
	var fallbackName, fallbackMAC string
	for _, entry := range entries {
		if entry.Name() == "lo" {
			continue
		}
		if mac, err := interfaceMAC(entry.Name()); err == nil {
			if fallbackName == "" {
				fallbackName, fallbackMAC = entry.Name(), mac
			}
			if _, statErr := os.Stat(filepath.Join("/sys/class/net", entry.Name(), "device")); statErr == nil {
				return entry.Name(), mac, nil
			}
		}
	}
	if fallbackName != "" {
		return fallbackName, fallbackMAC, nil
	}
	return "", "", errors.New("no usable non-loopback MAC address found")
}

func discoverInterfaceByMAC(wanted string) (string, string, error) {
	wanted = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(wanted), ":", ""))
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", "", fmt.Errorf("cannot inspect network interfaces")
	}
	for _, entry := range entries {
		if entry.Name() == "lo" {
			continue
		}
		mac, err := interfaceMAC(entry.Name())
		if err == nil && mac == wanted {
			return entry.Name(), mac, nil
		}
	}
	return "", "", errors.New("saved MAC address is not present")
}

func interfaceMAC(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join("/sys/class/net", name, "address"))
	if err != nil {
		return "", err
	}
	mac, err := net.ParseMAC(strings.TrimSpace(string(b)))
	if err != nil || len(mac) != 6 {
		return "", errors.New("invalid MAC address")
	}
	return strings.ToUpper(strings.ReplaceAll(mac.String(), ":", "")), nil
}

func localIP(name string) string {
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
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return ""
}

func kernelVersion() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return runtime.GOOS + "-" + runtime.GOARCH
	}
	return strings.TrimSpace(string(b))
}

func hardwareVersion() string {
	for _, path := range []string{"/proc/device-tree/model", "/sys/firmware/devicetree/base/model"} {
		b, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(b)) != "" {
			return strings.TrimRight(string(b), "\x00\n")
		}
	}
	return "oec-rk3566"
}

func hostUsage() (*float64, *float64) {
	var memoryPercent *float64
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available float64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			switch fields[0] {
			case "MemTotal:":
				total, _ = strconv.ParseFloat(fields[1], 64)
			case "MemAvailable:":
				available, _ = strconv.ParseFloat(fields[1], 64)
			}
		}
		if total > 0 && available >= 0 && available <= total {
			value := (total - available) / total * 100
			memoryPercent = &value
		}
	}
	return nil, memoryPercent
}

func validateURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("cloud URL must be an absolute HTTPS URL")
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return d
}

func envBool(name string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func fatal(format string, args ...any) {
	log.Printf("error: "+format, args...)
	os.Exit(1)
}
