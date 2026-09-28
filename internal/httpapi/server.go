package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/customer"
	"tygateway/internal/identity"
	"tygateway/internal/model"
	"tygateway/internal/providers"
	"tygateway/internal/rules"
	"tygateway/internal/store"
	"tygateway/internal/subscription"
)

//go:embed web/index.html web/portal.html web/enrollments.js
var webFS embed.FS

type Server struct {
	Store              store.Store
	RequireActivation  bool
	AdminToken         string
	AdminPassword      string
	RecoverySigningKey ed25519.PrivateKey
	RecoveryKeyID      string
	SubscriptionKey    []byte
	CustomerSessionKey []byte
	OfflineAfter       time.Duration
	AllowHTTPSubs      bool
	RuleCacheDir       string
	Rescue             *model.RescueConfig
	LegacyFRPRetired   bool
	AutoFRP            *model.AutoFRPConfig
	AutoFRPPortStart   int
	AutoFRPPortEnd     int
	FRPS               FRPSAdminConfig
	FRPRosterToken     string // Dedicated read-only token; never reuse administrator credentials.
	FRPRosterPortStart int
	FRPRosterPortEnd   int
	Engine             *rules.Engine
	Nonces             *auth.NonceCache
	Logger             *log.Logger
	registrationLimit  windowLimit
	adminLimit         windowLimit
	adminLoginLimit    keyedLimit
	adminLoginGlobal   windowLimit
	adminSessionsMu    sync.Mutex
	adminSessions      map[string]time.Time
	customerLoginLimit windowLimit
	customerLimits     keyedLimit
	recoveryLimits     keyedLimit
}

// FRPSAdminConfig contains public rescue endpoint metadata only. It must never
// hold an SSH password or FRP authentication secret.
type FRPSAdminConfig struct {
	Host            string
	ControlPort     int
	RemotePortStart int
	RemotePortEnd   int
}

type rescueDeviceView struct {
	ID              string     `json:"id"`
	DeviceNumber    int64      `json:"device_number"`
	Serial          string     `json:"serial"`
	MAC             string     `json:"mac"`
	Name            string     `json:"name"`
	Email           string     `json:"email,omitempty"`
	Note            string     `json:"note,omitempty"`
	State           string     `json:"state"`
	DeviceOnline    bool       `json:"device_online"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	Subscription    string     `json:"subscription,omitempty"`
	RemotePort      int        `json:"remote_port,omitempty"`
	FRPSHost        string     `json:"frps_host,omitempty"`
	FRPSControlPort int        `json:"frps_control_port,omitempty"`
	FRPPortStart    int        `json:"frp_port_start,omitempty"`
	FRPPortEnd      int        `json:"frp_port_end,omitempty"`
	FRPMode         string     `json:"frp_mode,omitempty"`
	PortAssigned    bool       `json:"port_assigned"`
	PortAvailable   bool       `json:"port_available"`
	TunnelStatus    string     `json:"tunnel_status"`
}

type rescueOverview struct {
	Host               string             `json:"host,omitempty"`
	ControlPort        int                `json:"control_port"`
	RemotePortStart    int                `json:"remote_port_start"`
	RemotePortEnd      int                `json:"remote_port_end"`
	LegacyRetired      bool               `json:"legacy_retired"`
	AutoFRPHost        string             `json:"auto_frp_host,omitempty"`
	AutoFRPControlPort int                `json:"auto_frp_control_port,omitempty"`
	AutoFRPPortStart   int                `json:"auto_frp_port_start,omitempty"`
	AutoFRPPortEnd     int                `json:"auto_frp_port_end,omitempty"`
	Devices            []rescueDeviceView `json:"devices"`
}

func NewServer(st store.Store, adminToken string, subscriptionKey []byte) *Server {
	return &Server{Store: st, AdminToken: adminToken, SubscriptionKey: subscriptionKey, CustomerSessionKey: customer.SessionKey(subscriptionKey), OfflineAfter: 90 * time.Second, FRPS: FRPSAdminConfig{ControlPort: 7001, RemotePortStart: 22000, RemotePortEnd: 22999}, AutoFRPPortStart: 22000, AutoFRPPortEnd: 22999, FRPRosterPortStart: 22000, FRPRosterPortEnd: 22999, Engine: rules.New(), Nonces: auth.NewNonceCache(10 * time.Minute), Logger: log.New(io.Discard, "", 0)}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/admin", http.StatusFound)
		return
	}
	if r.URL.Path == "/healthz" {
		s.health(w, r)
		return
	}
	if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
		s.adminPage(w)
		return
	}
	if r.URL.Path == "/portal" || r.URL.Path == "/portal/" {
		s.portalPage(w)
		return
	}
	if r.URL.Path == "/assets/enrollments.js" {
		b, err := webFS.ReadFile("web/enrollments.js")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(b)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		s.api(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if p, ok := s.Store.(interface{ Ping(context.Context) error }); ok {
		if err := p.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "database unavailable"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "ty-cloud"})
}

func (s *Server) adminPage(w http.ResponseWriter) {
	b, err := webFS.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) portalPage(w http.ResponseWriter) {
	b, err := webFS.ReadFile("web/portal.html")
	if err != nil {
		http.Error(w, "portal unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case path == "/admin/login" && r.Method == http.MethodPost:
		s.adminLogin(w, r)
		return
	case path == "/admin/session" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": s.isAdmin(r)})
		return
	case path == "/admin/logout" && r.Method == http.MethodPost:
		if !s.isAdminSession(r) || !sameOrigin(r) {
			writeError(w, http.StatusUnauthorized, "admin authentication required")
			return
		}
		s.revokeAdminSession(r)
		clearAdminCookie(w)
		w.WriteHeader(http.StatusNoContent)
		return
	case path == "/devices/register" && r.Method == http.MethodPost:
		if !s.registrationLimit.allow(200) {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "registration rate exceeded")
			return
		}
		s.register(w, r)
		return
	case path == "/frp/roster" && r.Method == http.MethodGet:
		s.frpRoster(w, r)
		return
	case path == "/customer/login" && r.Method == http.MethodPost:
		if !s.customerLoginLimit.allow(300) {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "login rate exceeded")
			return
		}
		s.customerLogin(w, r)
		return
	case strings.HasPrefix(path, "/customer/"):
		s.customerAPI(w, r, path)
		return
	case strings.HasPrefix(path, "/device/"):
		s.deviceAPI(w, r, path)
		return
	case strings.HasPrefix(path, "/admin/"):
		if !s.adminLimit.allow(600) {
			w.Header().Set("Retry-After", "60")
			writeError(w, 429, "admin rate exceeded")
			return
		}
		if !s.isAdmin(r) {
			writeError(w, http.StatusUnauthorized, "admin authentication required")
			return
		}
		s.adminAPI(w, r, path)
		return
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in model.RegisterDeviceInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid request")
		return
	}
	if in.IP == "" {
		in.IP = remoteIP(r)
	}
	var d model.Device
	var secret string
	var err error
	if in.ActivationCode != "" {
		d, secret, err = s.Store.RegisterApprovedDevice(r.Context(), in)
	} else if s.RequireActivation {
		d, secret, err = s.Store.RegisterMACClaim(r.Context(), in)
	} else {
		d, secret, err = s.Store.RegisterDevice(r.Context(), in)
	}
	if err != nil {
		if errors.Is(err, store.ErrInvalidActivation) {
			writeError(w, http.StatusForbidden, "device activation rejected")
			return
		}
		if store.IsAlreadyRegistered(err) {
			writeError(w, http.StatusConflict, "device already registered; secret is not returned")
			return
		}
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "device activation conflicts with an existing assignment")
			return
		}
		if errors.Is(err, identity.ErrInvalidMAC) {
			writeError(w, 400, "invalid MAC address")
			return
		}
		writeError(w, 500, "registration failed")
		return
	}
	macClaim := s.RequireActivation && in.ActivationCode == ""
	autoClaim := macClaim || !s.RequireActivation
	if d.RescueSSHPort == 0 && ((autoClaim && s.AutoFRP != nil) || (!macClaim && !s.LegacyFRPRetired && s.Rescue != nil)) && (d.State == model.DeviceEnabled || !s.RequireActivation) {
		var port int
		var allocateErr error
		if autoClaim && s.AutoFRP != nil {
			port, allocateErr = s.allocateAutoFRPPort(r.Context(), d.ID)
		} else if validRescuePortRange(s.FRPS) {
			port, allocateErr = s.allocateRescuePort(r.Context(), d.ID)
		} else {
			allocateErr = errors.New("rescue port range is unavailable")
		}
		if allocateErr != nil {
			// Rescue is optional. Do not strand a newly enrolled device just
			// because the finite rescue pool is exhausted; an administrator can
			// assign a port later without re-enrollment.
			s.Logger.Printf("automatic rescue port allocation failed for device %s: %v", d.ID, allocateErr)
		} else {
			d.RescueSSHPort = port
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"device": d.CustomerView(), "credentials": map[string]string{"device_id": d.ID, "device_secret": secret}, "rescue": s.rescueConfigForDevice(d)})
}

func validRescuePortRange(config FRPSAdminConfig) bool {
	return config.RemotePortStart >= 1 && config.RemotePortStart <= config.RemotePortEnd && config.RemotePortEnd <= 65535
}

// Probe before reserving a candidate. Probing after reservation can mistake
// this device's newly connected FRPC for a foreign listener during a retry,
// then clear a live tunnel. The unique index remains the final arbiter when
// two Cloud workers race for the same free candidate.
func (s *Server) allocateRescuePort(ctx context.Context, deviceID string) (int, error) {
	if s.Rescue == nil || !validRescuePortRange(s.FRPS) {
		return 0, errors.New("rescue port allocation is not configured")
	}
	return s.allocatePortInRange(ctx, deviceID, s.Rescue.Host, s.FRPS.RemotePortStart, s.FRPS.RemotePortEnd)
}

func (s *Server) validAutoFRPPortRange() bool {
	return s.AutoFRPPortStart >= 1 && s.AutoFRPPortStart <= s.AutoFRPPortEnd && s.AutoFRPPortEnd <= 65535
}

func (s *Server) allocateAutoFRPPort(ctx context.Context, deviceID string) (int, error) {
	if s.AutoFRP == nil || !s.validAutoFRPPortRange() {
		return 0, errors.New("automatic FRP is not configured")
	}
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return 0, err
	}
	if d.RescueSSHPort > 0 {
		if d.RescueSSHPort < s.AutoFRPPortStart || d.RescueSSHPort > s.AutoFRPPortEnd {
			return 0, errors.New("device already has a rescue port outside the isolated automatic FRP range")
		}
		return d.RescueSSHPort, nil
	}
	// The dedicated listener's port pool is reserved by the Cloud database;
	// unlike the legacy listener, it is not probed one TCP port at a time.
	return s.Store.AllocateRescueSSHPort(ctx, deviceID, s.AutoFRPPortStart, s.AutoFRPPortEnd)
}

func (s *Server) allocatePortInRange(ctx context.Context, deviceID, host string, start, end int) (int, error) {
	if strings.TrimSpace(host) == "" || start < 1 || start > end || end > 65535 {
		return 0, errors.New("rescue port allocation range is invalid")
	}
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return 0, err
	}
	if d.RescueSSHPort > 0 {
		return d.RescueSSHPort, nil
	}
	devices, err := s.Store.ListDevices(ctx, s.OfflineAfter)
	if err != nil {
		return 0, err
	}
	used := make(map[int]bool, len(devices))
	for _, device := range devices {
		if device.ID == deviceID && device.RescueSSHPort > 0 {
			return device.RescueSSHPort, nil
		}
		if device.RescueSSHPort > 0 {
			used[device.RescueSSHPort] = true
		}
	}
	for candidate := start; candidate <= end; candidate++ {
		if used[candidate] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		conn, probeErr := (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(strings.TrimSpace(host), strconv.Itoa(candidate)))
		if probeErr == nil {
			_ = conn.Close()
			continue
		}
		if conn != nil {
			_ = conn.Close()
		}
		// A refused/filtered port is the normal state for an unused FRPS
		// remote port. The database enforces uniqueness even if the probe is
		// inconclusive because the Cloud-to-FRPS path is temporarily down.
		port, err := s.Store.AllocateRescueSSHPort(ctx, deviceID, candidate, candidate)
		if errors.Is(err, store.ErrLimit) {
			continue
		}
		if err != nil {
			return 0, err
		}
		return port, nil
	}
	// A concurrent request for this same device could have won while we
	// probed; preserve its sticky assignment even if the range now looks full.
	current, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return 0, err
	}
	if current.RescueSSHPort > 0 {
		return current.RescueSSHPort, nil
	}
	return 0, store.ErrLimit
}

func (s *Server) rescueConfigForDevice(d model.Device) *model.RescueConfig {
	if s.Rescue == nil || s.LegacyFRPRetired {
		return nil
	}
	rescue := *s.Rescue
	rescue.RemotePort = d.RescueSSHPort
	return &rescue
}

func (s *Server) autoFRPConfigForDevice(d model.Device) *model.AutoFRPConfig {
	if s.AutoFRP == nil || !s.validAutoFRPPortRange() || d.State != model.DeviceEnabled || d.RescueSSHPort < s.AutoFRPPortStart || d.RescueSSHPort > s.AutoFRPPortEnd {
		return nil
	}
	config := *s.AutoFRP
	config.RemotePort = d.RescueSSHPort
	return &config
}

func (s *Server) rescueRouteForDevice(ctx context.Context, deviceID string) (host string, controlPort, portStart, portEnd int, mode string, err error) {
	d, err := s.Store.GetDevice(ctx, deviceID)
	if err != nil {
		return "", 0, 0, 0, "", err
	}
	if s.AutoFRP != nil && s.validAutoFRPPortRange() && (d.RescueSSHPort == 0 || d.RescueSSHPort >= s.AutoFRPPortStart && d.RescueSSHPort <= s.AutoFRPPortEnd) {
		enrollments, listErr := s.Store.ListDeviceEnrollments(ctx)
		if listErr != nil {
			return "", 0, 0, 0, "", listErr
		}
		for _, enrollment := range enrollments {
			if enrollment.DeviceID == d.ID && enrollment.ClaimedAt != nil && enrollment.ClaimMode == "mac" {
				return s.AutoFRP.Host, s.AutoFRP.ControlPort, s.AutoFRPPortStart, s.AutoFRPPortEnd, "per-device", nil
			}
		}
	}
	if s.LegacyFRPRetired {
		return "", 0, 0, 0, "", errors.New("legacy FRP listener is retired")
	}
	if !validRescuePortRange(s.FRPS) {
		return "", 0, 0, 0, "", errors.New("legacy rescue port range is unavailable")
	}
	return s.FRPS.Host, s.FRPS.ControlPort, s.FRPS.RemotePortStart, s.FRPS.RemotePortEnd, "legacy", nil
}

func (s *Server) deviceAPI(w http.ResponseWriter, r *http.Request, path string) {
	body, err := readBody(r)
	if err != nil {
		writeError(w, 400, "invalid body")
		return
	}
	deviceID := strings.Trim(path, "/")
	parts := strings.Split(deviceID, "/")
	if len(parts) < 2 || parts[0] != "device" {
		writeError(w, 404, "not found")
		return
	}
	id := parts[1]
	a, err := s.Store.GetDeviceAuth(r.Context(), id)
	if err != nil || a.ID != strings.TrimSpace(r.Header.Get("X-TY-Device")) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if a.State == model.DeviceDisabled {
		writeError(w, http.StatusForbidden, "device disabled")
		return
	}
	if !s.verifyDeviceRequest(r, body, a) {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if s.RequireActivation && a.State == model.DevicePending {
		if len(parts) < 3 || (parts[2] != "heartbeat" && parts[2] != "status") {
			writeError(w, http.StatusForbidden, "device activation pending")
			return
		}
	}
	if len(parts) >= 3 {
		switch parts[2] {
		case "heartbeat":
			if r.Method != http.MethodPost {
				writeError(w, 405, "method not allowed")
				return
			}
			s.heartbeat(w, r, id, body)
			return
		case "status":
			if r.Method != http.MethodPost {
				writeError(w, 405, "method not allowed")
				return
			}
			s.status(w, r, id, body)
			return
		case "config":
			if r.Method != http.MethodGet {
				writeError(w, 405, "method not allowed")
				return
			}
			s.config(w, r, id)
			return
		case "nodes":
			if len(parts) != 3 || r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.validatedNodes(w, r, id, body)
			return
		case "commands":
			if len(parts) == 3 && r.Method == http.MethodGet {
				s.commands(w, r, id)
				return
			}
			if len(parts) == 5 && parts[4] == "ack" && r.Method == http.MethodPost {
				s.ack(w, r, id, parts[3], body)
				return
			}
		case "customer":
			if len(parts) < 4 {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			d, err := s.Store.GetDevice(r.Context(), id)
			if err != nil || d.State == model.DeviceDisabled {
				writeError(w, http.StatusForbidden, "device unavailable")
				return
			}
			// deviceAPI reads the body once for HMAC verification. Rewind it for
			// the same strict customer-operation validators used by the browser
			// portal.
			r.Body = io.NopCloser(bytes.NewReader(body))
			s.deviceCustomerAPI(w, r, id, strings.Join(parts[3:], "/"), d)
			return
		}
	}
	writeError(w, 404, "not found")
}

func (s *Server) verifyDeviceRequest(r *http.Request, body []byte, a model.DeviceAuth) bool {
	// The raw bootstrap secret is never stored. The device derives the HMAC key
	// as SHA-256(secret), and the server stores only that derived value.
	return auth.VerifyRequest(r, body, a.SecretHash, time.Now().UTC(), s.Nonces, 5*time.Minute) == nil
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request, id string, body []byte) {
	var report model.DeviceReport
	if err := json.Unmarshal(body, &report); err != nil {
		writeError(w, 400, "invalid report")
		return
	}
	if !validDaeReport(report) {
		writeError(w, 400, "invalid dae status report")
		return
	}
	d, err := s.Store.Heartbeat(r.Context(), id, report)
	if err != nil {
		writeError(w, 500, "heartbeat failed")
		return
	}
	if err := s.applyDaeReport(r.Context(), d, report); err != nil {
		writeError(w, 500, "dae status update failed")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "device": d.CustomerView()})
}
func (s *Server) status(w http.ResponseWriter, r *http.Request, id string, body []byte) {
	var report model.DeviceReport
	if err := json.Unmarshal(body, &report); err != nil {
		writeError(w, 400, "invalid report")
		return
	}
	if !validDaeReport(report) {
		writeError(w, 400, "invalid dae status report")
		return
	}
	d, err := s.Store.Heartbeat(r.Context(), id, report)
	if err != nil {
		writeError(w, 500, "status update failed")
		return
	}
	if err := s.applyDaeReport(r.Context(), d, report); err != nil {
		writeError(w, 500, "dae status update failed")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "device": d.CustomerView()})
}

func validDaeReport(r model.DeviceReport) bool {
	if r.DaeStatus == "" {
		return true
	}
	switch r.DaeStatus {
	case "ok":
		return r.DaeSubscriptionID != "" && r.DaeNodeCount > 0 && r.DaeNodeCount <= 10000
	case "error":
		return r.DaeNodeCount >= 0 && r.DaeNodeCount <= 10000 && (r.DaeSubscriptionID != "" || r.DaeNodeCount == 0)
	case "unbound":
		return r.DaeSubscriptionID == "" && r.DaeNodeCount == 0
	default:
		return false
	}
}

func (s *Server) applyDaeReport(ctx context.Context, d model.Device, r model.DeviceReport) error {
	if r.DaeStatus == "" || r.DaeSubscriptionID == "" || d.SubscriptionID == "" || r.DaeSubscriptionID != d.SubscriptionID {
		return nil // ignore stale reports after a rebind/unbind
	}
	nodeCount := r.DaeNodeCount
	if r.DaeStatus != "ok" {
		nodeCount = -1 // retain the last known-good count on device-side errors
	}
	return s.Store.UpdateSubscriptionStatus(ctx, d.SubscriptionID, r.DaeStatus, nodeCount)
}

// The device reports only the identities dae accepted after a successful
// reload. The provider URL, proxy endpoints and credentials never enter this
// customer-facing inventory.
func (s *Server) validatedNodes(w http.ResponseWriter, r *http.Request, deviceID string, body []byte) {
	var report struct {
		SubscriptionID string               `json:"subscription_id"`
		Nodes          []model.CustomerNode `json:"nodes"`
	}
	if len(body) > 128<<10 || json.Unmarshal(body, &report) != nil || len(report.Nodes) == 0 || len(report.Nodes) > 512 {
		writeError(w, http.StatusBadRequest, "invalid node inventory")
		return
	}
	seenID, seenName := map[string]bool{}, map[string]bool{}
	for _, node := range report.Nodes {
		if len(node.ID) != 16 || len(node.Name) == 0 || len(node.Name) > 255 || subscription.IsIPv6NamedNode(node.Name) || strings.ContainsAny(node.Name, "\r\n\x00") || seenID[node.ID] || seenName[node.Name] {
			writeError(w, http.StatusBadRequest, "invalid node inventory")
			return
		}
		if _, err := hex.DecodeString(node.ID); err != nil || node.Region != "" || node.Group != "" {
			writeError(w, http.StatusBadRequest, "invalid node inventory")
			return
		}
		seenID[node.ID], seenName[node.Name] = true, true
	}
	if err := s.Store.CommitValidatedNodes(r.Context(), deviceID, report.SubscriptionID, report.Nodes); err != nil {
		if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusConflict, "subscription binding changed")
		} else {
			writeError(w, http.StatusServiceUnavailable, "node inventory unavailable")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": len(report.Nodes)})
}

func (s *Server) config(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	d, rs, nodes, prefs, err := s.policySnapshot(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "device not found")
		} else {
			writeError(w, http.StatusServiceUnavailable, "device configuration temporarily unavailable")
		}
		return
	}
	autoFRPApproved := false
	if d.State == model.DeviceEnabled && (s.AutoFRP != nil || (!s.LegacyFRPRetired && d.RescueSSHPort == 0 && s.Rescue != nil)) {
		enrollments, listErr := s.Store.ListDeviceEnrollments(r.Context())
		if listErr != nil {
			s.Logger.Printf("rescue enrollment lookup will retry for device %s: %v", d.ID, listErr)
			if s.AutoFRP != nil {
				writeError(w, http.StatusServiceUnavailable, "device authorization temporarily unavailable")
				return
			}
		} else {
			for _, enrollment := range enrollments {
				if enrollment.DeviceID != d.ID || enrollment.ClaimedAt == nil {
					continue
				}
				autoFRPApproved = enrollment.ClaimMode == "mac"
				if d.RescueSSHPort != 0 {
					break
				}
				// A MAC-claimed device must wait for the isolated automatic FRP
				// listener. Reserving a legacy port now would be sticky and would
				// prevent it from receiving an automatic FRP configuration later.
				if enrollment.ClaimMode == "mac" && s.AutoFRP == nil {
					break
				}
				var port int
				var allocationErr error
				if autoFRPApproved && s.AutoFRP != nil {
					port, allocationErr = s.allocateAutoFRPPort(r.Context(), d.ID)
				} else if !s.LegacyFRPRetired && s.Rescue != nil && validRescuePortRange(s.FRPS) {
					port, allocationErr = s.allocateRescuePort(r.Context(), d.ID)
				} else {
					allocationErr = errors.New("rescue port range is unavailable")
				}
				if allocationErr != nil {
					// Keep serving the last-known-good policy. The next config
					// poll retries this optional rescue-port reservation.
					s.Logger.Printf("rescue port allocation will retry for device %s: %v", d.ID, allocationErr)
				} else {
					d.RescueSSHPort = port
				}
				break
			}
		}
	}
	compiled := s.Engine.CompilePolicy(activePolicy(d, rs, nodes, prefs))
	basePolicy := rules.Policy(d, rs, nil, nodes, false)
	base := s.Engine.CompilePolicy(rules.ApplyNodePreferences(basePolicy, prefs, nodes))
	for i := range nodes {
		nodes[i].Params = nil
	}
	var daeSubscription *model.DaeSubscription
	if d.SubscriptionID != "" {
		ciphertext, err := s.Store.GetSubscriptionCiphertext(r.Context(), d.SubscriptionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "device subscription unavailable")
			return
		}
		rawURL, err := subscription.DecryptURL(ciphertext, s.SubscriptionKey)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "device subscription unavailable")
			return
		}
		daeSubscription = &model.DaeSubscription{ID: d.SubscriptionID, URL: rawURL}
	}
	var autoFRP *model.AutoFRPConfig
	if autoFRPApproved {
		autoFRP = s.autoFRPConfigForDevice(d)
	}
	writeJSON(w, 200, model.DeviceConfig{RulePackageVersion: d.RulePackageVersion, Device: d.CustomerView(), Profile: d.Profile, ConfigVersion: d.ConfigVersion, Rules: compiled, BaseRules: base, Preferences: prefs, ValidUntil: d.CustomerOverrideUntil, ServerTime: time.Now().UTC(), Nodes: nodes, Rescue: s.rescueConfigForDevice(d), AutoFRP: autoFRP, DaeSubscriptionManaged: true, DaeSubscription: daeSubscription})
}
func (s *Server) commands(w http.ResponseWriter, r *http.Request, id string) {
	cs, err := s.Store.PollCommands(r.Context(), id)
	if err != nil {
		writeError(w, 500, "commands unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"commands": cs})
}
func (s *Server) ack(w http.ResponseWriter, r *http.Request, deviceID, id string, body []byte) {
	var v struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &v); err != nil || (v.Status != "ok" && v.Status != "error" && v.Status != "completed" && v.Status != "failed") {
		writeError(w, 400, "invalid acknowledgement")
		return
	}
	if err := s.Store.AckCommand(r.Context(), deviceID, id, v.Status); err != nil {
		writeError(w, 404, "command not found")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) adminAPI(w http.ResponseWriter, r *http.Request, path string) {
	switch {
	case path == "/admin/enrollments" && r.Method == http.MethodGet:
		s.listEnrollments(w, r)
		return
	case path == "/admin/enrollments" && r.Method == http.MethodPost:
		s.prepareEnrollment(w, r)
		return
	case path == "/admin/enrollments/revoke" && r.Method == http.MethodPost:
		s.revokeEnrollment(w, r)
		return
	case path == "/admin/rescue" && r.Method == http.MethodGet:
		s.adminRescueOverview(w, r)
		return
	case path == "/admin/rescue/probe" && r.Method == http.MethodPost:
		s.adminRescueProbe(w, r)
		return
	case path == "/admin/devices/rescue-port" && r.Method == http.MethodPost:
		s.updateRescuePort(w, r)
		return
	case path == "/admin/devices/identity" && r.Method == http.MethodPost:
		s.updateIdentity(w, r)
		return
	case path == "/admin/devices/customer-access" && r.Method == http.MethodPost:
		s.issueCustomerAccess(w, r)
		return
	case path == "/admin/devices/reset-customer-settings" && r.Method == http.MethodPost:
		s.adminResetCustomerSettings(w, r)
		return
	case path == "/admin/devices/software" && r.Method == http.MethodGet:
		s.adminSoftwareStatus(w, r)
		return
	case path == "/admin/devices/software" && r.Method == http.MethodPost:
		s.adminSoftwareCommand(w, r)
		return
	case path == "/admin/recovery/issue" && r.Method == http.MethodPost:
		s.issueRecoveryAuthorization(w, r)
		return
	case path == "/admin/devices/lookup" && r.Method == http.MethodPost:
		s.lookupIdentity(w, r)
		return
	case path == "/admin/devices" && r.Method == http.MethodGet:
		d, err := s.Store.ListDevices(r.Context(), s.OfflineAfter)
		if err != nil {
			writeError(w, 500, "devices unavailable")
			return
		}
		writeJSON(w, 200, map[string]any{"devices": d})
		return
	case path == "/admin/subscriptions" && r.Method == http.MethodGet:
		v, err := s.Store.ListSubscriptions(r.Context())
		if err != nil {
			writeError(w, 500, "subscriptions unavailable")
			return
		}
		writeJSON(w, 200, map[string]any{"subscriptions": v})
		return
	case path == "/admin/subscriptions" && r.Method == http.MethodPost:
		s.createSubscription(w, r)
		return
	case path == "/admin/subscriptions/delete" && r.Method == http.MethodPost:
		s.deleteSubscription(w, r)
		return
	case path == "/admin/subscriptions/reveal" && r.Method == http.MethodPost:
		s.revealSubscription(w, r)
		return
	case path == "/admin/rules" && r.Method == http.MethodGet:
		deviceID := r.URL.Query().Get("device_id")
		v, err := s.Store.ListRules(r.Context(), deviceID)
		if err != nil {
			writeError(w, 500, "rules unavailable")
			return
		}
		writeJSON(w, 200, map[string]any{"rules": v})
		return
	case path == "/admin/rules" && r.Method == http.MethodPost:
		s.createRule(w, r)
		return
	case path == "/admin/rules/delete" && r.Method == http.MethodPost:
		var v struct {
			ID string `json:"id"`
		}
		if decodeJSON(r, &v) != nil || v.ID == "" {
			writeError(w, 400, "rule id required")
			return
		}
		if err := s.Store.DeleteRule(r.Context(), v.ID); err != nil {
			writeError(w, 404, "rule not found")
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	case path == "/admin/rules/explain" && r.Method == http.MethodPost:
		s.explain(w, r)
		return
	case path == "/admin/rules/compile" && r.Method == http.MethodPost:
		s.compile(w, r)
		return
	case path == "/admin/providers/import" && r.Method == http.MethodPost:
		s.importProvider(w, r)
		return
	case path == "/admin/devices/update" && r.Method == http.MethodPost:
		s.updateDevice(w, r)
		return
	case path == "/admin/devices/command" && r.Method == http.MethodPost:
		s.enqueueCommand(w, r)
		return
	case path == "/admin/devices/bind-subscription" && r.Method == http.MethodPost:
		s.bindSubscription(w, r)
		return
	case path == "/admin/subscriptions/refresh" && r.Method == http.MethodPost:
		s.refreshSubscription(w, r)
		return
	case path == "/admin/provider-catalog" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"categories": providers.Catalog(), "profiles": rules.SupportedProfiles()})
		return
	case path == "/admin/rule-packages" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"packages": rulePackageCatalog()})
		return
	case path == "/admin/rule-package" && r.Method == http.MethodPost:
		d, e := s.Store.GetDevice(r.Context(), r.URL.Query().Get("device_id"))
		if e != nil {
			writeError(w, 404, "device not found")
			return
		}
		s.customerRulePackage(w, r, d)
		return
	}
	writeError(w, 404, "not found")
}

func (s *Server) adminRescueOverview(w http.ResponseWriter, r *http.Request) {
	devices, err := s.Store.ListDevices(r.Context(), s.OfflineAfter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rescue devices unavailable")
		return
	}
	subscriptions, err := s.Store.ListSubscriptions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rescue subscriptions unavailable")
		return
	}
	if !s.LegacyFRPRetired && (s.FRPS.RemotePortStart < 1 || s.FRPS.RemotePortEnd < s.FRPS.RemotePortStart || s.FRPS.RemotePortEnd > 65535) {
		writeError(w, http.StatusServiceUnavailable, "rescue port range is not configured")
		return
	}
	autoApproved := map[string]bool{}
	if s.AutoFRP != nil {
		enrollments, enrollmentErr := s.Store.ListDeviceEnrollments(r.Context())
		if enrollmentErr != nil {
			writeError(w, http.StatusServiceUnavailable, "automatic FRP device inventory unavailable")
			return
		}
		for _, enrollment := range enrollments {
			if enrollment.ClaimedAt != nil && enrollment.DeviceID != "" && enrollment.ClaimMode == "mac" {
				autoApproved[enrollment.DeviceID] = true
			}
		}
	}
	subscriptionNames := make(map[string]string, len(subscriptions))
	for _, sub := range subscriptions {
		subscriptionNames[sub.ID] = sub.Name
	}
	result := rescueOverview{Host: strings.TrimSpace(s.FRPS.Host), ControlPort: s.FRPS.ControlPort, RemotePortStart: s.FRPS.RemotePortStart, RemotePortEnd: s.FRPS.RemotePortEnd, LegacyRetired: s.LegacyFRPRetired, Devices: make([]rescueDeviceView, 0, len(devices))}
	if s.AutoFRP != nil && s.validAutoFRPPortRange() {
		result.AutoFRPHost = s.AutoFRP.Host
		result.AutoFRPControlPort = s.AutoFRP.ControlPort
		result.AutoFRPPortStart = s.AutoFRPPortStart
		result.AutoFRPPortEnd = s.AutoFRPPortEnd
		if s.LegacyFRPRetired {
			result.Host = s.AutoFRP.Host
			result.ControlPort = s.AutoFRP.ControlPort
			result.RemotePortStart = s.AutoFRPPortStart
			result.RemotePortEnd = s.AutoFRPPortEnd
		}
	}
	for _, d := range devices {
		entry := rescueDeviceView{ID: d.ID, DeviceNumber: d.DeviceNumber, Serial: d.Serial, MAC: d.MAC, Name: d.Name, Email: d.Email, Note: d.Note, State: string(d.State), DeviceOnline: d.Online, LastSeen: d.LastSeen, Subscription: subscriptionNames[d.SubscriptionID], TunnelStatus: "unverified"}
		if d.RescueSSHPort > 0 {
			entry.RemotePort = d.RescueSSHPort
			entry.PortAssigned = true
		}
		if s.AutoFRP != nil && autoApproved[d.ID] && s.validAutoFRPPortRange() && (d.RescueSSHPort == 0 || d.RescueSSHPort >= s.AutoFRPPortStart && d.RescueSSHPort <= s.AutoFRPPortEnd) {
			entry.FRPMode = "per-device"
			entry.FRPSHost = s.AutoFRP.Host
			entry.FRPSControlPort = s.AutoFRP.ControlPort
			entry.FRPPortStart, entry.FRPPortEnd = s.AutoFRPPortStart, s.AutoFRPPortEnd
			entry.PortAvailable = d.RescueSSHPort >= s.AutoFRPPortStart && d.RescueSSHPort <= s.AutoFRPPortEnd
		} else if !s.LegacyFRPRetired && d.RescueSSHPort >= s.FRPS.RemotePortStart && d.RescueSSHPort <= s.FRPS.RemotePortEnd {
			entry.FRPMode = "legacy"
			entry.FRPSHost = strings.TrimSpace(s.FRPS.Host)
			entry.FRPSControlPort = s.FRPS.ControlPort
			entry.FRPPortStart, entry.FRPPortEnd = s.FRPS.RemotePortStart, s.FRPS.RemotePortEnd
			entry.PortAvailable = true
		}
		result.Devices = append(result.Devices, entry)
	}
	writeJSON(w, http.StatusOK, result)
}

// adminRescueProbe performs an on-demand SSH-banner check against the
// configured FRPS endpoint and this device's explicitly assigned reserved port.
// The FRPS host is deployment configuration, never caller-controlled.
func (s *Server) adminRescueProbe(w http.ResponseWriter, r *http.Request) {
	var v struct {
		DeviceID string `json:"device_id"`
	}
	if decodeJSON(r, &v) != nil || strings.TrimSpace(v.DeviceID) == "" {
		writeError(w, http.StatusBadRequest, "device_id required")
		return
	}
	devices, err := s.Store.ListDevices(r.Context(), s.OfflineAfter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rescue devices unavailable")
		return
	}
	var device *model.Device
	for i := range devices {
		if devices[i].ID == v.DeviceID {
			device = &devices[i]
			break
		}
	}
	if device == nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	host, _, start, end, _, routeErr := s.rescueRouteForDevice(r.Context(), device.ID)
	if routeErr != nil || strings.TrimSpace(host) == "" || start < 1 || end < start || end > 65535 {
		writeError(w, http.StatusServiceUnavailable, "rescue endpoint is not configured")
		return
	}
	port := device.RescueSSHPort
	if port < start || port > end {
		writeError(w, http.StatusConflict, "device has no assigned rescue port in the configured range")
		return
	}
	checkedAt := time.Now().UTC()
	result := map[string]any{"device_id": device.ID, "port": port, "reachable": false, "tunnel_status": "unreachable", "checked_at": checkedAt}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
	if err == nil {
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		banner, readErr := bufio.NewReader(conn).ReadString('\n')
		if readErr == nil && strings.HasPrefix(banner, "SSH-") {
			result["reachable"] = true
			result["tunnel_status"] = "ssh_ready"
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) updateRescuePort(w http.ResponseWriter, r *http.Request) {
	var v struct {
		DeviceID string `json:"device_id"`
		Port     *int   `json:"port"`
	}
	if decodeJSON(r, &v) != nil || strings.TrimSpace(v.DeviceID) == "" || v.Port == nil || *v.Port < 0 {
		writeError(w, http.StatusBadRequest, "device_id and a non-negative port are required")
		return
	}
	deviceID, port := strings.TrimSpace(v.DeviceID), *v.Port
	start, end := 0, 0
	var routeErr error
	if port != 0 {
		_, _, start, end, _, routeErr = s.rescueRouteForDevice(r.Context(), deviceID)
	} else {
		_, routeErr = s.Store.GetDevice(r.Context(), deviceID)
	}
	if routeErr != nil {
		if errors.Is(routeErr, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "device not found")
		} else {
			writeError(w, http.StatusServiceUnavailable, "rescue route unavailable")
		}
		return
	}
	if port != 0 && (start < 1 || end < start || port < start || port > end) {
		writeError(w, http.StatusBadRequest, "port is outside the configured FRPS range")
		return
	}
	if err := s.Store.SetRescueSSHPort(r.Context(), deviceID, port); err != nil {
		switch {
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "port is already assigned to another device")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "device not found")
		default:
			writeError(w, http.StatusInternalServerError, "rescue port could not be saved")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "device_id": deviceID, "port": port})
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID      string            `json:"id"`
		State   model.DeviceState `json:"state"`
		Note    string            `json:"note"`
		Profile string            `json:"profile"`
	}
	if decodeJSON(r, &v) != nil || v.ID == "" {
		writeError(w, 400, "device id required")
		return
	}
	if v.State != "" && v.State != model.DevicePending && v.State != model.DeviceEnabled && v.State != model.DeviceDisabled {
		writeError(w, 400, "invalid device state")
		return
	}
	if v.Profile != "" && v.Profile != rules.ProfileGFW && v.Profile != rules.ProfileBlackmatrix && packageNames[v.Profile] == "" {
		writeError(w, 400, "invalid profile")
		return
	}
	if packageNames[v.Profile] != "" {
		if _, err := loadRulePackage(v.Profile); err != nil {
			writeError(w, 409, err.Error())
			return
		}
		current, e := s.Store.GetDevice(r.Context(), v.ID)
		if e != nil || !supportsManagedRulePackages(current.AgentVersion) {
			writeError(w, 409, "请先升级设备 Agent 至 0.6.0 或更高版本")
			return
		}
	}
	d, err := s.Store.UpdateDevice(r.Context(), v.ID, v.State, v.Note, v.Profile)
	if err != nil {
		writeError(w, 404, "device not found")
		return
	}
	writeJSON(w, 200, map[string]any{"device": d})
}
func (s *Server) enqueueCommand(w http.ResponseWriter, r *http.Request) {
	var c model.Command
	if decodeJSON(r, &c) != nil || c.DeviceID == "" || c.Command == "" {
		writeError(w, 400, "device_id and command required")
		return
	}
	if c.Command != "reload_config" && c.Command != "report_status" {
		writeError(w, 400, "unsupported command")
		return
	}
	c, err := s.Store.EnqueueCommand(r.Context(), c)
	if err != nil {
		writeError(w, 500, "command queue failed")
		return
	}
	writeJSON(w, 201, c)
}
func (s *Server) createRule(w http.ResponseWriter, r *http.Request) {
	var rule model.Rule
	if decodeJSON(r, &rule) != nil || rule.MatchType == "" || rule.MatchValue == "" || rule.Action == "" {
		writeError(w, 400, "match_type, match_value and action required")
		return
	}
	if rule.Source == "" {
		rule.Source = "user"
	}
	// Rules created in the administrator console are the editable baseline;
	// customer-owned rules use source=customer and win on overlap.
	rule.ID, rule.Source, rule.SourceType = "", "admin", "admin"
	if rule.Priority < 0 || rule.Priority > 10000 {
		writeError(w, 400, "invalid priority")
		return
	}
	switch rule.MatchType {
	case "domain", "domain_exact", "domain_suffix", "domain_keyword", "ip", "cidr", "ip_cidr":
	default:
		writeError(w, 400, "unsupported match type")
		return
	}
	if strings.ContainsAny(rule.MatchValue+rule.Action, "\r\n") || len(rule.MatchValue) > 1024 {
		writeError(w, 400, "invalid rule")
		return
	}
	if rule.MatchType == "ip" || rule.MatchType == "cidr" || rule.MatchType == "ip_cidr" {
		normalized, err := rules.NormalizeIPMatchValue(rule.MatchValue)
		if err != nil {
			writeError(w, 400, "invalid IP/CIDR rule")
			return
		}
		rule.MatchValue = normalized
	}
	rule.Enabled = true
	created, err := s.Store.CreateRule(r.Context(), rule)
	if err != nil {
		writeError(w, 500, "rule create failed")
		return
	}
	writeJSON(w, 201, created)
}
func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	var q model.ExplainRequest
	if decodeJSON(r, &q) != nil || q.DeviceID == "" {
		writeError(w, 400, "device_id required")
		return
	}
	d, rs, nodes, prefs, err := s.policySnapshot(r.Context(), q.DeviceID)
	if err != nil {
		writeError(w, 404, "device not found")
		return
	}
	writeJSON(w, 200, s.Engine.ExplainPolicy(d.Profile, activePolicy(d, rs, nodes, prefs), rules.Query{Domain: q.Domain, IP: q.IP, SourceIP: q.SourceIP, SourceMAC: q.SourceMAC, CountryCode: q.CountryCode, IsLAN: q.IsLAN, IsManagement: q.IsManagement}))
}

func (s *Server) compile(w http.ResponseWriter, r *http.Request) {
	var v struct {
		DeviceID string `json:"device_id"`
	}
	if decodeJSON(r, &v) != nil || v.DeviceID == "" {
		writeError(w, 400, "device_id required")
		return
	}
	d, rulesForDevice, nodes, prefs, err := s.policySnapshot(r.Context(), v.DeviceID)
	if err != nil {
		writeError(w, 404, "device not found")
		return
	}
	compiled := s.Engine.CompilePolicy(activePolicy(d, rulesForDevice, nodes, prefs))
	writeJSON(w, 200, map[string]any{"device_id": d.ID, "profile": d.Profile, "config_version": d.ConfigVersion, "candidate_dae": rules.RenderDaeCandidate(d.Profile, compiled), "rules": compiled})
}
func (s *Server) importProvider(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Provider string `json:"provider"`
		Content  string `json:"content"`
	}
	if decodeJSON(r, &v) != nil || v.Provider == "" || v.Content == "" {
		writeError(w, 400, "provider and content required")
		return
	}
	if err := providers.ValidateProviderName(v.Provider); err != nil {
		writeError(w, 400, "invalid provider")
		return
	}
	parsed, err := providers.ParseClashRules(v.Provider, v.Content)
	if err != nil {
		writeError(w, 422, "provider parse failed; existing rules were kept")
		return
	}
	if err := s.Store.ReplaceProviderRules(r.Context(), v.Provider, parsed); err != nil {
		writeError(w, 500, "provider replace failed; existing rules were kept")
		return
	}
	s.saveLKG(v.Provider, v.Content)
	writeJSON(w, 200, map[string]any{"provider": v.Provider, "rule_count": len(parsed), "summary": providers.Summary(parsed)})
}
func (s *Server) saveLKG(provider, content string) {
	if s.RuleCacheDir == "" {
		return
	}
	if err := os.MkdirAll(s.RuleCacheDir, 0700); err != nil {
		return
	}
	name := filepath.Join(s.RuleCacheDir, identity.NewID()+"-"+safeFileName(provider)+".rules")
	_ = os.WriteFile(name, []byte(content), 0600)
}
func (s *Server) refreshSubscription(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID string `json:"id"`
	}
	if decodeJSON(r, &v) != nil || v.ID == "" {
		writeError(w, 400, "subscription id required")
		return
	}
	if _, err := s.Store.GetSubscriptionCiphertext(r.Context(), v.ID); err != nil {
		writeError(w, 404, "subscription not found")
		return
	}
	devices, err := s.Store.ListDevices(r.Context(), s.OfflineAfter)
	if err != nil {
		writeError(w, 500, "subscription device lookup failed")
		return
	}
	var bound *model.Device
	for i := range devices {
		if devices[i].SubscriptionID == v.ID {
			bound = &devices[i]
			break
		}
	}
	if bound == nil {
		writeError(w, http.StatusConflict, "bind this subscription to a device before requesting a dae refresh")
		return
	}
	if err := s.Store.UpdateSubscriptionStatus(r.Context(), v.ID, "pending", -1); err != nil {
		writeError(w, 500, "subscription status update failed")
		return
	}
	if _, err := s.Store.EnqueueCommand(r.Context(), model.Command{DeviceID: bound.ID, Command: "refresh_subscription"}); err != nil {
		_ = s.Store.UpdateSubscriptionStatus(r.Context(), v.ID, "error", -1)
		writeError(w, 500, "device refresh could not be queued")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": v.ID, "status": "pending", "parser": "dae_on_device"})
}
func (s *Server) createSubscription(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Name     string `json:"name"`
		Provider string `json:"provider"`
		URL      string `json:"url"`
	}
	if decodeJSON(r, &v) != nil || strings.TrimSpace(v.Name) == "" || strings.TrimSpace(v.URL) == "" {
		writeError(w, 400, "name and url required")
		return
	}
	if err := subscription.ValidateURL(v.URL, s.AllowHTTPSubs); err != nil {
		writeError(w, 400, "unsafe subscription URL")
		return
	}
	ciphertext, err := subscription.EncryptURL(v.URL, s.SubscriptionKey)
	if err != nil {
		writeError(w, 503, "subscription encryption is not configured")
		return
	}
	created, err := s.Store.CreateSubscription(r.Context(), v.Name, v.Provider, ciphertext, lookupDigest(v.URL, s.SubscriptionKey))
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, 409, "subscription already exists")
			return
		}
		writeError(w, 500, "subscription create failed")
		return
	}
	writeJSON(w, 201, created)
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID string `json:"id"`
	}
	if decodeJSON(r, &v) != nil || strings.TrimSpace(v.ID) == "" {
		writeError(w, http.StatusBadRequest, "subscription id required")
		return
	}
	detached, err := s.Store.DeleteSubscription(r.Context(), strings.TrimSpace(v.ID))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "subscription not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "subscription delete failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "detached_devices": detached})
}

func (s *Server) bindSubscription(w http.ResponseWriter, r *http.Request) {
	var v struct {
		DeviceID       string `json:"device_id"`
		SubscriptionID string `json:"subscription_id"`
	}
	if decodeJSON(r, &v) != nil || v.DeviceID == "" || v.SubscriptionID == "" {
		writeError(w, 400, "device_id and subscription_id required")
		return
	}
	if err := s.Store.BindSubscription(r.Context(), v.DeviceID, v.SubscriptionID); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, 409, "subscription already bound")
		} else {
			writeError(w, 400, "binding unavailable")
		}
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) isAdmin(r *http.Request) bool {
	if s.isAdminSession(r) {
		return true
	}
	if s.AdminToken == "" {
		return false
	}
	token := strings.TrimSpace(r.Header.Get("X-TY-Admin-Token"))
	if token == "" {
		authz := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
			token = strings.TrimSpace(authz[7:])
		}
	}
	return hmac.Equal([]byte(token), []byte(s.AdminToken))
}

const (
	adminCookieName    = "__Host-ty-admin"
	adminSessionExpiry = 8 * time.Hour
)

func (s *Server) adminLogin(w http.ResponseWriter, r *http.Request) {
	peer := loginPeer(r)
	if !s.adminLoginLimit.allow(peer, 5) || !s.adminLoginGlobal.allow(30) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "login rate exceeded")
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	if s.AdminPassword == "" {
		writeError(w, http.StatusServiceUnavailable, "password login is not configured")
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if decodeJSON(r, &input) != nil || len(input.Password) == 0 || len(input.Password) > 4096 {
		writeError(w, http.StatusBadRequest, "invalid login request")
		return
	}
	want := sha256.Sum256([]byte(s.AdminPassword))
	got := sha256.Sum256([]byte(input.Password))
	if !hmac.Equal(want[:], got[:]) {
		writeError(w, http.StatusUnauthorized, "invalid password")
		return
	}
	token, err := s.newAdminSession()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "login unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: adminCookieName, Value: token, Path: "/", MaxAge: int(adminSessionExpiry.Seconds()),
		Expires: time.Now().Add(adminSessionExpiry), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
}

func (s *Server) newAdminSession() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	now := time.Now()
	s.adminSessionsMu.Lock()
	defer s.adminSessionsMu.Unlock()
	if s.adminSessions == nil {
		s.adminSessions = make(map[string]time.Time)
	}
	for id, expires := range s.adminSessions {
		if !expires.After(now) {
			delete(s.adminSessions, id)
		}
	}
	if len(s.adminSessions) >= 4096 {
		return "", errors.New("too many administrator sessions")
	}
	s.adminSessions[token] = now.Add(adminSessionExpiry)
	return token, nil
}

func (s *Server) isAdminSession(r *http.Request) bool {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	now := time.Now()
	s.adminSessionsMu.Lock()
	expires, ok := s.adminSessions[cookie.Value]
	if ok && !expires.After(now) {
		delete(s.adminSessions, cookie.Value)
		ok = false
	}
	s.adminSessionsMu.Unlock()
	return ok
}

func (s *Server) revokeAdminSession(r *http.Request) {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		return
	}
	s.adminSessionsMu.Lock()
	delete(s.adminSessions, cookie.Value)
	s.adminSessionsMu.Unlock()
}

func sameOrigin(r *http.Request) bool {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Host != r.Host || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return false
	}
	return true
}

func clearAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: adminCookieName, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
}

func decodeJSON(r *http.Request, v any) error {
	body, err := readBody(r)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return errors.New("empty body")
	}
	return json.Unmarshal(body, v)
}
func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 2<<20 {
		return nil, errors.New("body too large")
	}
	return body, nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func safeFileName(v string) string {
	v = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, v)
	return v
}
