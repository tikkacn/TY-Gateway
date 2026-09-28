package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"tygateway/internal/httpapi"
	"tygateway/internal/model"
	"tygateway/internal/recovery"
	"tygateway/internal/store"
	"tygateway/internal/subscription"
)

func main() {
	dsn := strings.TrimSpace(os.Getenv("TY_DB_DSN"))
	st, closer, err := store.NewFromEnv(dsn)
	if err != nil {
		log.Fatal("store initialization failed")
	}
	if closer != nil {
		defer closer.Close()
	}

	adminToken := strings.TrimSpace(os.Getenv("TY_ADMIN_TOKEN"))
	adminPassword := os.Getenv("TY_ADMIN_PASSWORD")
	if adminToken == "" {
		if dsn == "" || dsn == "memory://" {
			adminToken = "local-dev-admin"
		}
	}
	if strings.TrimSpace(adminPassword) == "" {
		if dsn != "" && dsn != "memory://" {
			log.Fatal("TY_ADMIN_PASSWORD is required when using a database")
		}
		adminPassword = "local-dev-admin"
		log.Print("warning: using local development admin password; set TY_ADMIN_PASSWORD before deployment")
	}
	keyText := strings.TrimSpace(os.Getenv("TY_SUBSCRIPTION_KEY"))
	var key []byte
	if keyText != "" && !strings.HasPrefix(keyText, "replace-with-") {
		key, err = subscription.KeyFromString(keyText)
		if err != nil {
			log.Fatal("invalid TY_SUBSCRIPTION_KEY")
		}
	}
	if len(key) == 0 {
		if dsn != "" && dsn != "memory://" {
			log.Fatal("TY_SUBSCRIPTION_KEY is required when using a database")
		}
		key, _ = subscription.KeyFromString("local-development-only-key")
	}

	srv := httpapi.NewServer(st, adminToken, key)
	srv.FRPRosterToken = strings.TrimSpace(os.Getenv("TY_FRP_ROSTER_TOKEN"))
	if srv.FRPRosterToken != "" && (len(srv.FRPRosterToken) < 32 || strings.HasPrefix(srv.FRPRosterToken, "replace-with-") || srv.FRPRosterToken == adminToken || srv.FRPRosterToken == adminPassword) {
		log.Fatal("TY_FRP_ROSTER_TOKEN must be a distinct random value of at least 32 characters")
	}
	if v := os.Getenv("TY_FRP_ROSTER_PORT_START"); v != "" {
		p, e := strconv.Atoi(v)
		if e != nil || p < 1 || p > 65535 {
			log.Fatal("invalid TY_FRP_ROSTER_PORT_START")
		}
		srv.FRPRosterPortStart = p
	}
	if v := os.Getenv("TY_FRP_ROSTER_PORT_END"); v != "" {
		p, e := strconv.Atoi(v)
		if e != nil || p < 1 || p > 65535 {
			log.Fatal("invalid TY_FRP_ROSTER_PORT_END")
		}
		srv.FRPRosterPortEnd = p
	}
	if srv.FRPRosterPortStart > srv.FRPRosterPortEnd {
		log.Fatal("invalid FRP roster port range")
	}
	// Existing authenticated devices continue to work. Persistent Cloud accepts
	// new claims only for MACs pre-registered in its enrollment table.
	srv.RequireActivation = dsn != "" && dsn != "memory://"
	srv.AdminPassword = adminPassword
	recoveryKeyText := strings.TrimSpace(os.Getenv("TY_RECOVERY_SIGNING_KEY"))
	srv.RecoveryKeyID = strings.TrimSpace(os.Getenv("TY_RECOVERY_KEY_ID"))
	if recoveryKeyText != "" {
		srv.RecoverySigningKey, err = recovery.ParsePrivateKey(recoveryKeyText)
		if err != nil {
			log.Fatal("invalid TY_RECOVERY_SIGNING_KEY")
		}
		if srv.RecoveryKeyID == "" {
			log.Fatal("TY_RECOVERY_KEY_ID is required when recovery signing is enabled")
		}
	} else if srv.RecoveryKeyID != "" {
		log.Fatal("TY_RECOVERY_SIGNING_KEY is required when TY_RECOVERY_KEY_ID is set")
	}
	if d := os.Getenv("TY_OFFLINE_AFTER"); d != "" {
		if v, e := time.ParseDuration(d); e == nil && v > 0 {
			srv.OfflineAfter = v
		}
	}
	srv.AllowHTTPSubs = os.Getenv("TY_ALLOW_HTTP_SUBSCRIPTIONS") == "1"
	srv.RuleCacheDir = strings.TrimSpace(os.Getenv("TY_RULE_CACHE_DIR"))
	srv.FRPS.Host = strings.TrimSpace(os.Getenv("TY_FRPS_HOST"))
	if strings.TrimSpace(os.Getenv("TY_RESCUE_HOST")) != "" {
		log.Fatal("legacy FRP listener is retired; remove TY_RESCUE_HOST before enabling the unified automatic channel")
	}
	srv.LegacyFRPRetired = true
	controlPort, portErr := parseSharedFRPSControlPort(os.Getenv("TY_FRPS_CONTROL_PORT"))
	if portErr != nil {
		log.Fatal(portErr)
	}
	srv.FRPS.ControlPort = controlPort
	if p, e := strconv.Atoi(os.Getenv("TY_FRPS_REMOTE_PORT_START")); e == nil && p > 0 && p <= 65535 {
		srv.FRPS.RemotePortStart = p
	}
	if p, e := strconv.Atoi(os.Getenv("TY_FRPS_REMOTE_PORT_END")); e == nil && p > 0 && p <= 65535 {
		srv.FRPS.RemotePortEnd = p
	}
	if dsn != "" && dsn != "memory://" && os.Getenv("TY_FRP_AUTO_ENABLED") != "1" {
		log.Fatal("production Cloud requires TY_FRP_AUTO_ENABLED=1 after retiring the legacy FRP listener")
	}
	if os.Getenv("TY_FRP_AUTO_ENABLED") == "1" {
		host := strings.TrimSpace(os.Getenv("TY_FRPS_HOST"))
		caPath := strings.TrimSpace(os.Getenv("TY_FRP_AUTO_CA_FILE"))
		if host == "" || caPath == "" {
			log.Fatal("TY_FRP_AUTO_ENABLED requires TY_FRPS_HOST and TY_FRP_AUTO_CA_FILE")
		}
		ca, readErr := os.ReadFile(caPath)
		if readErr != nil || len(ca) == 0 || len(ca) > 1<<20 {
			log.Fatal("could not read bounded FRP auto-client CA bundle")
		}
		block, _ := pem.Decode(ca)
		if block == nil {
			log.Fatal("TY_FRP_AUTO_CA_FILE must contain a valid CA certificate")
		}
		cert, certErr := x509.ParseCertificate(block.Bytes)
		if certErr != nil || !cert.IsCA {
			log.Fatal("TY_FRP_AUTO_CA_FILE must contain a valid CA certificate")
		}
		controlPort := srv.FRPS.ControlPort
		if value := os.Getenv("TY_FRP_AUTO_CONTROL_PORT"); value != "" {
			p, parseErr := strconv.Atoi(value)
			if parseErr != nil || p != controlPort {
				log.Fatal("TY_FRP_AUTO_CONTROL_PORT must match TY_FRPS_CONTROL_PORT; FRPC and FRPS use one shared control port")
			}
		}
		start, end := srv.FRPS.RemotePortStart, srv.FRPS.RemotePortEnd
		if value := os.Getenv("TY_FRP_AUTO_PORT_START"); value != "" {
			p, parseErr := strconv.Atoi(value)
			if parseErr != nil || p != 22000 {
				log.Fatal("TY_FRP_AUTO_PORT_START must match the shared FRPS mapping pool start (22000)")
			}
		}
		if value := os.Getenv("TY_FRP_AUTO_PORT_END"); value != "" {
			p, parseErr := strconv.Atoi(value)
			if parseErr != nil || p != 22999 {
				log.Fatal("TY_FRP_AUTO_PORT_END must match the shared FRPS mapping pool end (22999)")
			}
		}
		if start != 22000 || end != 22999 {
			log.Fatal("automatic FRP requires the shared FRPS mapping pool TY_FRPS_REMOTE_PORT_START=22000 and TY_FRPS_REMOTE_PORT_END=22999")
		}
		if srv.FRPRosterPortStart != start || srv.FRPRosterPortEnd != end {
			log.Fatal("FRP roster port range must match the shared FRPS mapping pool 22000-22999")
		}
		if srv.FRPRosterToken == "" {
			log.Fatal("TY_FRP_AUTO_ENABLED requires a separate TY_FRP_ROSTER_TOKEN")
		}
		srv.AutoFRP = &model.AutoFRPConfig{Host: host, ControlPort: controlPort, TLSCA: string(ca)}
		srv.AutoFRPPortStart, srv.AutoFRPPortEnd = start, end
		srv.FRPRosterPortStart, srv.FRPRosterPortEnd = start, end
	}

	addr := os.Getenv("TY_LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9080"
	}
	log.Printf("ty-cloud listening on %s (storage=%s)", addr, storageName(dsn))
	server := &http.Server{Addr: addr, Handler: srv, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func parseSharedFRPSControlPort(value string) (int, error) {
	const port = 7001
	value = strings.TrimSpace(value)
	if value == "" {
		return port, nil
	}
	configured, err := strconv.Atoi(value)
	if err != nil || configured != port {
		return 0, errors.New("TY_FRPS_CONTROL_PORT must be 7001; FRPC serverPort and FRPS bindPort share this control port")
	}
	return port, nil
}

func storageName(dsn string) string {
	if dsn == "" || dsn == "memory://" {
		return "memory"
	}
	return "mysql"
}
