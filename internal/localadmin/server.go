package localadmin

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tygateway/internal/hostnet"
	"tygateway/internal/identity"
	"tygateway/internal/recovery"
)

//go:embed web/index.html
var staticFiles embed.FS

const (
	sessionCookie = "ty_local_session"
	sessionTTL    = 8 * time.Hour
	maxBodyBytes  = 64 << 10
)

type Config struct {
	NetworkSocket     string
	UpdateSocket      string
	AgentSocket       string
	StateDir          string
	InterfaceName     string
	DeviceCode        string
	RecoveryKeyID     string
	RecoveryPublicKey ed25519.PublicKey
	Now               func() time.Time
}

type recoveryChallenge struct {
	Value   string
	Created time.Time
}

type rateWindow struct {
	Started time.Time
	Count   int
}

type Server struct {
	cfg         Config
	password    passwordRecord
	hasPassword bool
	network     NetworkSettings
	networkMu   sync.Mutex
	sessions    map[[32]byte]time.Time
	challenge   *recoveryChallenge
	rate        map[string]rateWindow
	mu          sync.Mutex
	handler     http.Handler
}

type apiError struct {
	Error string `json:"error"`
}

func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.StateDir) == "" {
		return nil, errors.New("local manager state directory is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if (cfg.RecoveryKeyID == "") != (len(cfg.RecoveryPublicKey) == 0) {
		return nil, errors.New("recovery key ID and public key must be configured together")
	}
	if cfg.RecoveryKeyID != "" && !recovery.ValidKeyID(cfg.RecoveryKeyID) {
		return nil, errors.New("invalid local recovery key ID")
	}
	if len(cfg.RecoveryPublicKey) != 0 && len(cfg.RecoveryPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid recovery public key")
	}
	if cfg.DeviceCode != "" {
		serial, _, err := identity.NormalizeMAC(cfg.DeviceCode)
		if err != nil {
			return nil, errors.New("invalid configured device code")
		}
		cfg.DeviceCode = serial
	}
	if err := os.MkdirAll(cfg.StateDir, 0700); err != nil {
		return nil, fmt.Errorf("create local manager state directory: %w", err)
	}
	s := &Server{cfg: cfg, sessions: make(map[[32]byte]time.Time), rate: make(map[string]rateWindow)}
	if err := s.loadPassword(); err != nil {
		return nil, err
	}
	settings, err := loadNetworkSettings(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	s.network = settings
	s.handler = s.routes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	if !s.isLocalPeer(r.RemoteAddr) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "local network access required"})
		return
	}
	s.handler.ServeHTTP(w, r)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.serveIndex)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("POST /api/setup", s.setup)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("POST /api/logout", s.logout)
	mux.HandleFunc("GET /api/state", s.requireSession(s.state))
	mux.HandleFunc("GET /api/session", s.requireSession(s.state))
	mux.HandleFunc("POST /api/network/preview", s.requireSession(s.previewNetwork))
	mux.HandleFunc("GET /api/network/settings", s.requireSession(s.getNetworkSettings))
	mux.HandleFunc("GET /api/network/neighbors", s.requireSession(s.getNetworkNeighbors))
	mux.HandleFunc("PUT /api/network/settings", s.requireSession(s.putNetworkSettings))
	mux.HandleFunc("POST /api/network/apply", s.requireSession(s.applyNetworkAddress))
	mux.HandleFunc("GET /api/network/apply", s.requireSession(s.networkApplyStatus))
	mux.HandleFunc("POST /api/network/apply/confirm", s.requireSession(s.confirmNetworkAddress))
	mux.HandleFunc("GET /api/network/services", s.requireSession(s.lanServiceStatus))
	mux.HandleFunc("POST /api/network/services", s.requireSession(s.applyLANServices))
	mux.HandleFunc("GET /api/proxy", s.requireSession(s.getProxyStatus))
	mux.HandleFunc("POST /api/proxy", s.requireSession(s.setProxyStatus))
	mux.HandleFunc("GET /api/customer/me", s.requireSession(s.customerMe))
	mux.HandleFunc("GET /api/customer/rules", s.requireSession(s.customerRules))
	mux.HandleFunc("POST /api/customer/rules", s.requireSession(s.customerRules))
	mux.HandleFunc("POST /api/customer/rules/delete", s.requireSession(s.customerRules))
	mux.HandleFunc("POST /api/customer/override", s.requireSession(s.customerRules))
	mux.HandleFunc("POST /api/customer/node-preference", s.requireSession(s.customerRules))
	mux.HandleFunc("POST /api/customer/action", s.requireSession(s.customerRules))
	mux.HandleFunc("POST /api/customer/rule-package", s.requireSession(s.customerRules))
	mux.HandleFunc("POST /api/password", s.requireSession(s.changePassword))
	mux.HandleFunc("POST /api/recovery/challenge", s.issueChallenge)
	mux.HandleFunc("POST /api/recovery/reset", s.resetPassword)
	mux.HandleFunc("GET /api/software/status", s.requireSession(s.softwareStatus))
	mux.HandleFunc("POST /api/software/check", s.requireSession(s.softwareCheck))
	mux.HandleFunc("POST /api/software/apply", s.requireSession(s.softwareApply))
	mux.HandleFunc("POST /api/software/offline", s.requireSession(s.softwareOfflineApply))
	mux.HandleFunc("GET /api/config/export", s.requireSession(s.exportConfig))
	mux.HandleFunc("POST /api/config/preview", s.requireSession(s.previewConfigImport))
	mux.HandleFunc("POST /api/config/import", s.requireSession(s.importConfig))
	mux.HandleFunc("POST /api/config/reset", s.requireSession(s.resetCustomerConfig))
	return mux
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, err := staticFiles.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, "local interface unavailable", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	setupRequired := !s.hasPassword
	s.mu.Unlock()
	code := s.deviceCode()
	writeJSON(w, http.StatusOK, map[string]any{
		"setup_required":   setupRequired,
		"device_code":      code,
		"interface":        s.interfaceName(),
		"addresses":        s.interfaceAddresses(),
		"recovery_enabled": len(s.cfg.RecoveryPublicKey) == ed25519.PublicKeySize,
	})
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 5) {
		writeRateLimit(w)
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if !validPassword(input.Password) {
		writeJSON(w, http.StatusBadRequest, apiError{Error: errWeakPassword.Error()})
		return
	}
	token, tokenHash, err := newSessionToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not create session"})
		return
	}
	// Serialize first-time setup, so concurrent requests cannot race to replace
	// the initial administrator password.
	s.mu.Lock()
	if s.hasPassword {
		s.mu.Unlock()
		writeJSON(w, http.StatusConflict, apiError{Error: "local password is already configured"})
		return
	}
	record, err := newPasswordRecord(input.Password)
	if err != nil {
		s.mu.Unlock()
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not secure local password"})
		return
	}
	if err := s.savePassword(record); err != nil {
		s.mu.Unlock()
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not save local password"})
		return
	}
	s.password, s.hasPassword = record, true
	s.addSessionLocked(tokenHash)
	s.mu.Unlock()
	s.writeSessionCookie(w, token)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 8) {
		writeRateLimit(w)
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	s.mu.Lock()
	record, configured := s.password, s.hasPassword
	s.mu.Unlock()
	if !configured || !verifyPassword(input.Password, record) {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "password is incorrect"})
		return
	}
	token, tokenHash, err := newSessionToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not create session"})
		return
	}
	s.mu.Lock()
	if !s.hasPassword || s.password != record {
		s.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "password changed; try again"})
		return
	}
	s.clearExpiredSessionsLocked()
	s.addSessionLocked(tokenHash)
	s.mu.Unlock()
	s.writeSessionCookie(w, token)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, sha256.Sum256([]byte(cookie.Value)))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	controls := "draft_only"
	if s.cfg.NetworkSocket != "" {
		controls = "local_services"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":             s.deviceCode(),
		"interface":               s.interfaceName(),
		"addresses":               s.interfaceAddresses(),
		"default_gateway":         systemDefaultGateway(),
		"network_controls":        controls,
		"address_apply_available": s.cfg.NetworkSocket != "",
		"network_notice":          "应用地址前先确认其未被主路由 DHCP 地址池分配；地址变更须在新地址登录确认，超时将自动恢复。",
	})
}

func (s *Server) previewNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 10) {
		writeRateLimit(w)
		return
	}
	var input NetworkPlanInput
	if !decodeBody(w, r, &input) {
		return
	}
	preview, err := PreviewNetworkPlan(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: errInvalidNetworkPlan.Error()})
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) getNetworkSettings(w http.ResponseWriter, r *http.Request) {
	s.networkMu.Lock()
	settings := s.network
	s.networkMu.Unlock()
	writeJSON(w, http.StatusOK, s.networkSettingsResponse(settings))
}

func (s *Server) putNetworkSettings(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 10) {
		writeRateLimit(w)
		return
	}
	var settings NetworkSettings
	if !decodeBody(w, r, &settings) {
		return
	}
	validated, err := validateNetworkSettings(settings)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: errInvalidNetworkSettings.Error()})
		return
	}
	now := s.cfg.Now().UTC()
	validated.UpdatedAt = &now
	s.networkMu.Lock()
	if err := saveNetworkSettings(s.cfg.StateDir, validated); err != nil {
		s.networkMu.Unlock()
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not save local network preset"})
		return
	}
	s.network = validated
	s.networkMu.Unlock()
	writeJSON(w, http.StatusOK, s.networkSettingsResponse(validated))
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	s.mu.Lock()
	old := s.password
	s.mu.Unlock()
	if !verifyPassword(input.CurrentPassword, old) {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "current password is incorrect"})
		return
	}
	if !validPassword(input.NewPassword) {
		writeJSON(w, http.StatusBadRequest, apiError{Error: errWeakPassword.Error()})
		return
	}
	record, err := newPasswordRecord(input.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not secure local password"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.password != old {
		writeJSON(w, http.StatusConflict, apiError{Error: "password changed; sign in again"})
		return
	}
	if err := s.savePassword(record); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not save local password"})
		return
	}
	s.password = record
	s.revokeSessionsLocked()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) issueChallenge(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 5) {
		writeRateLimit(w)
		return
	}
	if len(s.cfg.RecoveryPublicKey) != ed25519.PublicKeySize || s.cfg.RecoveryKeyID == "" {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "offline password recovery is not configured on this device"})
		return
	}
	code := s.deviceCode()
	if code == "" {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "device identity is unavailable"})
		return
	}
	challenge, err := recovery.NewChallenge()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not create recovery challenge"})
		return
	}
	now := s.cfg.Now()
	s.mu.Lock()
	s.challenge = &recoveryChallenge{Value: challenge, Created: now}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code": code,
		"challenge":   challenge,
		"expires_at":  now.Add(recovery.ChallengeLifetime).UTC(),
	})
}

func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	if !s.validMutation(r) {
		writeJSON(w, http.StatusForbidden, apiError{Error: "request origin rejected"})
		return
	}
	if !s.allow(r, 5) {
		writeRateLimit(w)
		return
	}
	var input struct {
		Challenge     string `json:"challenge"`
		Authorization string `json:"authorization"`
		NewPassword   string `json:"new_password"`
	}
	if !decodeBody(w, r, &input) {
		return
	}
	if !validPassword(input.NewPassword) {
		writeJSON(w, http.StatusBadRequest, apiError{Error: errWeakPassword.Error()})
		return
	}
	code := s.deviceCode()
	s.mu.Lock()
	active := s.challenge
	if active == nil || s.cfg.Now().Sub(active.Created) > recovery.ChallengeLifetime || s.cfg.Now().Before(active.Created) || subtle.ConstantTimeCompare([]byte(active.Value), []byte(input.Challenge)) != 1 {
		s.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "challenge is invalid or expired; request a new one"})
		return
	}
	challenge := *active
	s.mu.Unlock()
	_, err := recovery.VerifyAt(map[string]ed25519.PublicKey{s.cfg.RecoveryKeyID: s.cfg.RecoveryPublicKey}, strings.TrimSpace(input.Authorization), code, challenge.Value, s.cfg.Now())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "recovery authorization is invalid"})
		return
	}
	record, err := newPasswordRecord(input.NewPassword)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not secure local password"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.challenge == nil || s.challenge.Value != challenge.Value || !s.challenge.Created.Equal(challenge.Created) || s.cfg.Now().Sub(s.challenge.Created) > recovery.ChallengeLifetime || s.cfg.Now().Before(s.challenge.Created) {
		writeJSON(w, http.StatusConflict, apiError{Error: "challenge was already used or expired; request a new one"})
		return
	}
	if err := s.savePassword(record); err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "could not save local password"})
		return
	}
	s.password, s.hasPassword = record, true
	s.challenge = nil
	s.revokeSessionsLocked()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || cookie.Value == "" {
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "sign in required"})
			return
		}
		hash := sha256.Sum256([]byte(cookie.Value))
		s.mu.Lock()
		expires, ok := s.sessions[hash]
		if ok && !s.cfg.Now().Before(expires) {
			delete(s.sessions, hash)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusUnauthorized, apiError{Error: "session expired"})
			return
		}
		next(w, r)
	}
}

func newSessionToken() (string, [32]byte, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", [32]byte{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	hash := sha256.Sum256([]byte(token))
	return token, hash, nil
}

func (s *Server) addSessionLocked(hash [32]byte) {
	s.clearExpiredSessionsLocked()
	s.sessions[hash] = s.cfg.Now().Add(sessionTTL)
}

func (s *Server) writeSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
}

func (s *Server) validMutation(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || r.Host == "" {
		return false
	}
	return origin == "http://"+r.Host
}

func (s *Server) allow(r *http.Request, max int) bool {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	window := s.rate[peer]
	if now.Sub(window.Started) >= time.Minute || now.Before(window.Started) {
		window = rateWindow{Started: now}
	}
	window.Count++
	s.rate[peer] = window
	return window.Count <= max
}

func (s *Server) isLocalPeer(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// Some home LANs use globally-scoped IPv6. Permit those only when the
	// peer belongs to an address prefix assigned directly to this OEC.
	for _, iface := range s.networkInterfaces() {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if cidr, ok := addr.(*net.IPNet); ok && cidr.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func (s *Server) networkInterfaces() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	preferred := s.cfg.InterfaceName
	if preferred != "" {
		for _, iface := range ifaces {
			if iface.Name == preferred && iface.Flags&net.FlagLoopback == 0 {
				return []net.Interface{iface}
			}
		}
		return nil
	}
	if preferred, _ := hostnet.DefaultRoute(); preferred != "" {
		for _, iface := range ifaces {
			if iface.Name == preferred && iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
				return []net.Interface{iface}
			}
		}
	}
	var result []net.Interface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback == 0 && iface.Flags&net.FlagUp != 0 {
			result = append(result, iface)
		}
	}
	return result
}

func (s *Server) interfaceName() string {
	ifaces := s.networkInterfaces()
	if len(ifaces) == 0 {
		return s.cfg.InterfaceName
	}
	return ifaces[0].Name
}

func (s *Server) interfaceAddresses() []string {
	var result []string
	for _, iface := range s.networkInterfaces() {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			result = append(result, addr.String())
		}
	}
	return result
}

func (s *Server) deviceCode() string {
	if s.cfg.DeviceCode != "" {
		return s.cfg.DeviceCode
	}
	for _, iface := range s.networkInterfaces() {
		if serial, _, err := identity.NormalizeMAC(iface.HardwareAddr.String()); err == nil {
			return serial
		}
	}
	return ""
}

func (s *Server) loadPassword() error {
	path := s.passwordPath()
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect local manager password: %w", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("local manager password file permissions are too broad")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read local manager password: %w", err)
	}
	var record passwordRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Algorithm != "PBKDF2-HMAC-SHA256" || record.Iterations < 100_000 || record.Iterations > 2_000_000 {
		return errors.New("local manager password file is invalid; refusing automatic reset")
	}
	s.password, s.hasPassword = record, true
	return nil
}

func (s *Server) savePassword(record passwordRecord) error {
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := s.passwordPath()
	tmp, err := os.CreateTemp(s.cfg.StateDir, ".local-admin-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	directory, err := os.Open(s.cfg.StateDir)
	if err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func (s *Server) passwordPath() string {
	return filepath.Join(s.cfg.StateDir, "local-admin.json")
}

func (s *Server) clearExpiredSessionsLocked() {
	now := s.cfg.Now()
	for tokenHash, expires := range s.sessions {
		if !now.Before(expires) {
			delete(s.sessions, tokenHash)
		}
	}
}

func (s *Server) revokeSessionsLocked() {
	for tokenHash := range s.sessions {
		delete(s.sessions, tokenHash)
	}
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) bool {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, apiError{Error: "application/json required"})
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeRateLimit(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusTooManyRequests, apiError{Error: "too many attempts; wait one minute"})
}
