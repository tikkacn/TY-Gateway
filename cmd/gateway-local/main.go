package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"tygateway/internal/localadmin"
	"tygateway/internal/recovery"
)

func main() {
	stateDir := envOr("TY_LOCAL_STATE_DIR", "/var/lib/ty-gateway-local")
	interfaceName := strings.TrimSpace(os.Getenv("TY_LOCAL_INTERFACE"))
	deviceCode := strings.TrimSpace(os.Getenv("TY_LOCAL_DEVICE_CODE"))
	listenAddress := envOr("TY_LOCAL_LISTEN_ADDR", ":8088")
	keyID := strings.TrimSpace(os.Getenv("TY_RECOVERY_KEY_ID"))
	publicKeyValue := strings.TrimSpace(os.Getenv("TY_RECOVERY_PUBLIC_KEY"))

	var publicKey []byte
	if publicKeyValue != "" {
		parsed, err := recovery.ParsePublicKey(publicKeyValue)
		if err != nil {
			log.Fatal("invalid local recovery public key")
		}
		publicKey = parsed
	}
	manager, err := localadmin.New(localadmin.Config{
		NetworkSocket:     strings.TrimSpace(os.Getenv("TY_LOCAL_NETWORK_SOCKET")),
		UpdateSocket:      envOr("TY_LOCAL_UPDATE_SOCKET", "/run/ty-gateway-update/control.sock"),
		AgentSocket:       envOr("TY_LOCAL_AGENT_SOCKET", "/run/ty-gateway-agent/control.sock"),
		StateDir:          stateDir,
		InterfaceName:     interfaceName,
		DeviceCode:        deviceCode,
		RecoveryKeyID:     keyID,
		RecoveryPublicKey: publicKey,
	})
	if err != nil {
		log.Fatalf("local manager initialization failed: %v", err)
	}
	server := &http.Server{
		Addr:              listenAddress,
		Handler:           manager,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       12 * time.Second,
		WriteTimeout:      130 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	log.Printf("local device manager listening on %s", listenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("local manager server failed: %v", err)
	}
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
