package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"tygateway/internal/auth"
	"tygateway/internal/frpauth"
	"tygateway/internal/model"
)

type autoFRPManager struct {
	mu         sync.Mutex
	binary     string
	configPath string
	caPath     string
	cmd        *exec.Cmd
	done       chan struct{}
	waitResult chan error
	configHash string
}

func newAutoFRPManager(configPath, binary string) *autoFRPManager {
	return &autoFRPManager{binary: binary, configPath: configPath, caPath: filepath.Join(filepath.Dir(configPath), "frp-auto-ca.pem")}
}

func (m *autoFRPManager) Apply(ctx context.Context, state credentialState, config *model.AutoFRPConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if config == nil {
		m.stopLocked()
		m.configHash = ""
		_ = os.Remove(m.configPath)
		_ = os.Remove(m.caPath)
		_ = os.Remove(m.configPath + ".next")
		return nil
	}
	text, _, err := renderAutoFRPConfig(state, config, m.caPath)
	if err != nil {
		return err
	}
	ca := []byte(config.TLSCA)
	if err := validateAutoFRPCA(ca); err != nil {
		return err
	}
	contentHash := sha256.Sum256(append(append([]byte(text), 0), ca...))
	newHash := hex.EncodeToString(contentHash[:])
	if newHash == m.configHash && m.cmd != nil && m.done != nil {
		select {
		case <-m.done:
			// The old process exited; fall through and recreate it.
		default:
			return nil
		}
	}
	if len(ca) == 0 || len(ca) > 1<<20 {
		return errors.New("automatic FRP CA bundle has an invalid size")
	}
	if err := os.MkdirAll(filepath.Dir(m.configPath), 0700); err != nil {
		return err
	}
	nextPath := m.configPath + ".next"
	caCandidatePath := m.caPath + ".candidate"
	defer os.Remove(caCandidatePath)
	candidateText, _, err := renderAutoFRPConfig(state, config, caCandidatePath)
	if err != nil {
		return err
	}
	if err := writePrivateFile(caCandidatePath, ca); err != nil {
		return errors.New("could not stage FRP server trust certificate")
	}
	if err := writePrivateFile(nextPath, []byte(candidateText)); err != nil {
		return errors.New("could not stage automatic FRP configuration")
	}
	defer os.Remove(nextPath)
	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	verifyOut, verifyErr := exec.CommandContext(verifyCtx, m.binary, "verify", "-c", nextPath).CombinedOutput()
	cancel()
	if verifyErr != nil {
		return fmt.Errorf("FRP rejected the generated configuration: %s", strings.TrimSpace(string(verifyOut)))
	}
	previousConfig, configReadErr := os.ReadFile(m.configPath)
	previousCA, caReadErr := os.ReadFile(m.caPath)
	hadPrevious := configReadErr == nil && caReadErr == nil
	m.stopLocked()
	if err := os.Rename(caCandidatePath, m.caPath); err != nil {
		m.restoreFiles(previousConfig, previousCA, hadPrevious)
		return errors.New("could not save FRP server trust certificate")
	}
	if err := writePrivateFile(nextPath, []byte(text)); err != nil {
		m.restoreFiles(previousConfig, previousCA, hadPrevious)
		return errors.New("could not stage verified FRP configuration")
	}
	if err := os.Rename(nextPath, m.configPath); err != nil {
		m.restoreFiles(previousConfig, previousCA, hadPrevious)
		return errors.New("could not activate generated FRP configuration")
	}
	if err := m.startLocked(ctx); err != nil {
		m.stopLocked()
		m.restoreFiles(previousConfig, previousCA, hadPrevious)
		if hadPrevious {
			if rollbackErr := m.startLocked(ctx); rollbackErr != nil {
				return fmt.Errorf("new FRP client failed and previous configuration could not be restarted: %w", err)
			}
		}
		return err
	}
	m.configHash = newHash
	return nil
}

func (m *autoFRPManager) restoreFiles(config, ca []byte, hadPrevious bool) {
	if !hadPrevious {
		_ = os.Remove(m.configPath)
		_ = os.Remove(m.caPath)
		m.configHash = ""
		return
	}
	_ = writePrivateFile(m.caPath, ca)
	_ = writePrivateFile(m.configPath, config)
}

func (m *autoFRPManager) startLocked(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cmd := exec.Command(m.binary, "-c", m.configPath)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start per-device FRP client: %w", err)
	}
	done, waitResult := make(chan struct{}), make(chan error, 1)
	m.cmd, m.done, m.waitResult = cmd, done, waitResult
	go func() {
		err := cmd.Wait()
		waitResult <- err
		close(done)
	}()
	timer := time.NewTimer(1200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		m.stopLocked()
		return ctx.Err()
	case <-done:
		exitErr := <-waitResult
		m.cmd, m.done, m.waitResult = nil, nil, nil
		if exitErr == nil {
			return errors.New("per-device FRP client exited immediately")
		}
		return fmt.Errorf("per-device FRP client exited immediately: %w", exitErr)
	case <-timer.C:
		return nil
	}
}

func (m *autoFRPManager) stopLocked() {
	cmd, done, waitResult := m.cmd, m.done, m.waitResult
	if cmd == nil {
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
	if waitResult != nil {
		select {
		case <-waitResult:
		default:
		}
	}
	if m.cmd == cmd {
		m.cmd, m.done, m.waitResult = nil, nil, nil
	}
}

func renderAutoFRPConfig(state credentialState, config *model.AutoFRPConfig, caPath string) (string, string, error) {
	if config == nil || state.DeviceID == "" || !validSecret(state.DeviceSecret) || !safeFRPHost(config.Host) || config.ControlPort != 7001 || config.RemotePort < 22000 || config.RemotePort > 22999 || strings.ContainsAny(state.DeviceID, ".:/\\\r\n\t ") {
		return "", "", errors.New("automatic FRP configuration is incomplete or unsafe")
	}
	credential, err := frpauth.Credential(auth.SecretHash(state.DeviceSecret), state.DeviceID, config.RemotePort)
	if err != nil {
		return "", "", errors.New("could not derive device-specific FRP credential")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = %s\nserverPort = %d\nuser = %s\nloginFailExit = true\n", strconv.Quote(config.Host), config.ControlPort, strconv.Quote(state.DeviceID))
	fmt.Fprintf(&b, "transport.tls.enable = true\ntransport.tls.trustedCaFile = %s\n", strconv.Quote(caPath))
	fmt.Fprintf(&b, "metadatas.device_id = %s\nmetadatas.rescue_key = %s\n", strconv.Quote(state.DeviceID), strconv.Quote(credential))
	// FRP prefixes every proxy name with the global `user`. Keep the local
	// proxy name unprefixed so FRPS and the authorization plugin see
	// `<device-id>.ssh-rescue`, not `<device-id>.<device-id>.ssh-rescue`.
	fmt.Fprintf(&b, "\n[[proxies]]\nname = %s\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = 22\nremotePort = %d\n", strconv.Quote("ssh-rescue"), config.RemotePort)
	return b.String(), credential, nil
}

func safeFRPHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\r\n/\\\"'") {
		return false
	}
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return true
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

func validateAutoFRPCA(ca []byte) error {
	if len(ca) == 0 || len(ca) > 1<<20 {
		return errors.New("automatic FRP CA bundle has an invalid size")
	}
	remaining := ca
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return errors.New("automatic FRP CA bundle is not valid PEM")
		}
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return errors.New("automatic FRP CA bundle contains an invalid non-CA certificate")
		}
		return nil
	}
	return errors.New("automatic FRP CA bundle contains no CA certificate")
}
