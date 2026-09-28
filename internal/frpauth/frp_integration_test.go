package frpauth

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tygateway/internal/frpoidc"
)

// Run with TY_FRP_TEST_FRPS and TY_FRP_TEST_FRPC pointing to a verified FRP
// 0.71.0 release. It binds only localhost and never contacts production.
func TestFRP071PlainSSHForwarding(t *testing.T) {
	frps, frpc := os.Getenv("TY_FRP_TEST_FRPS"), os.Getenv("TY_FRP_TEST_FRPC")
	if frps == "" || frpc == "" {
		t.Skip("verified FRP binaries not provided")
	}
	const serverToken = "test-only-frps-auth-token-0123456789abcdef"
	control, remote := freeLocalPort(t), freeLocalPort(t)
	localSSH, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localSSH.Close()
	go func() {
		for {
			conn, err := localSSH.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-ty-test\r\n"))
			_ = conn.Close()
		}
	}()
	dir := t.TempDir()
	serverConfig, clientConfig := filepath.Join(dir, "frps.toml"), filepath.Join(dir, "frpc.toml")
	serverText := fmt.Sprintf("bindAddr = \"127.0.0.1\"\nbindPort = %d\nproxyBindAddr = \"127.0.0.1\"\ntransport.tcpMux = false\ntransport.tls.force = true\nauth.token = %q\nallowPorts = [{start = %d, end = %d}]\nmaxPortsPerClient = 1\n", control, serverToken, remote, remote)
	clientText := fmt.Sprintf("serverAddr = \"127.0.0.1\"\nserverPort = %d\nauth.token = %q\nloginFailExit = true\ntransport.tcpMux = false\ntransport.tls.enable = true\n[[proxies]]\nname = \"ssh-rescue\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", control, serverToken, localSSH.Addr().(*net.TCPAddr).Port, remote)
	if err := os.WriteFile(serverConfig, []byte(serverText), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientConfig, []byte(clientText), 0600); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ binary, config string }{{frps, serverConfig}, {frpc, clientConfig}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, v.binary, "verify", "-c", v.config).CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("FRP config verify failed: %v %s", err, out)
		}
	}
	start := func(binary, config string) {
		cmd := exec.Command(binary, "-c", config)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	start(frps, serverConfig)
	if !waitTCP("127.0.0.1", control, 5*time.Second) {
		t.Fatal("local FRPS control listener did not start")
	}
	start(frpc, clientConfig)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(remote)), 300*time.Millisecond)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && line == "SSH-2.0-ty-test\r\n" {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("plain FRP 0.71.0 could not forward the local SSH greeting")
}

func TestFRP071RealSSHForwarding(t *testing.T) {
	frps, frpc := os.Getenv("TY_FRP_TEST_FRPS"), os.Getenv("TY_FRP_TEST_FRPC")
	if frps == "" || frpc == "" {
		t.Skip("verified FRP binaries not provided")
	}
	const id = "device-integration"
	remote := freeLocalPort(t)
	credential, err := Credential(strings.Repeat("a", 64), id, remote)
	if err != nil {
		t.Fatal(err)
	}
	plugin := NewPlugin(time.Hour, remote, remote)
	if err := plugin.SetRoster(Roster{GeneratedAt: time.Now().UTC(), Entries: []Entry{{DeviceID: id, Port: remote, CredentialHash: CredentialHash(credential)}}}); err != nil {
		t.Fatal(err)
	}
	var observedMu sync.Mutex
	observed := make(map[string]int)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedMu.Lock()
		observed[r.URL.Query().Get("op")]++
		observedMu.Unlock()
		plugin.ServeHTTP(w, r)
	}))
	defer hook.Close()
	hookAddr := strings.TrimPrefix(hook.URL, "http://")
	oidcKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var provider *frpoidc.Provider
	oidcHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { provider.ServeHTTP(w, r) }))
	defer oidcHTTP.Close()
	const audience = "ty-gateway-frp-test"
	provider = &frpoidc.Provider{Issuer: oidcHTTP.URL, Audience: audience, Key: oidcKey, VerifyClient: func(_ context.Context, clientID, clientSecret string) (string, error) {
		if clientID != id || clientSecret != credential {
			return "", fmt.Errorf("client denied")
		}
		return clientID, nil
	}}
	control := freeLocalPort(t)
	localSSH, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localSSH.Close()
	go func() {
		for {
			conn, err := localSSH.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("SSH-2.0-ty-test\r\n"))
			_ = conn.Close()
		}
	}()
	dir := t.TempDir()
	serverConfig := filepath.Join(dir, "frps.toml")
	clientConfig := filepath.Join(dir, "frpc.toml")
	serverText := fmt.Sprintf("log.level = \"debug\"\nbindAddr = \"127.0.0.1\"\nbindPort = %d\nproxyBindAddr = \"127.0.0.1\"\ntransport.tcpMux = false\ntransport.tls.force = true\nauth.method = \"oidc\"\nauth.oidc.issuer = %q\nauth.oidc.audience = %q\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\nallowPorts = [{start = %d, end = %d}]\nmaxPortsPerClient = 1\n[[httpPlugins]]\nname = \"ty-auth\"\naddr = \"%s\"\npath = \"/handler\"\nops = [\"Login\", \"NewProxy\", \"Ping\", \"NewWorkConn\", \"NewUserConn\", \"CloseProxy\"]\n", control, oidcHTTP.URL, audience, remote, remote, hookAddr)
	clientText := fmt.Sprintf("log.level = \"debug\"\nserverAddr = \"127.0.0.1\"\nserverPort = %d\nauth.method = \"oidc\"\nauth.additionalScopes = [\"HeartBeats\", \"NewWorkConns\"]\nauth.oidc.clientID = %q\nauth.oidc.clientSecret = %q\nauth.oidc.audience = %q\nauth.oidc.scope = \"frp\"\nauth.oidc.tokenEndpointURL = %q\nuser = \"%s\"\nmetadatas.device_id = \"%s\"\nmetadatas.rescue_key = \"%s\"\nloginFailExit = true\ntransport.tcpMux = false\ntransport.tls.enable = true\n[[proxies]]\nname = \"ssh-rescue\"\ntype = \"tcp\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\nremotePort = %d\n", control, id, credential, audience, oidcHTTP.URL+"/token", id, id, credential, localSSH.Addr().(*net.TCPAddr).Port, remote)
	if err := os.WriteFile(serverConfig, []byte(serverText), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientConfig, []byte(clientText), 0600); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ binary, config string }{{frps, serverConfig}, {frpc, clientConfig}} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, v.binary, "verify", "-c", v.config).CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("FRP config verify failed: %v %s", err, out)
		}
	}
	start := func(binary, config string) *exec.Cmd {
		cmd := exec.Command(binary, "-c", config)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		return cmd
	}
	// FRP's native OIDC verifier rejects a wrong device credential even before
	// the additional plugin roster policy is involved.
	noPluginPort := freeLocalPort(t)
	noPluginConfig := filepath.Join(dir, "frps-no-plugin.toml")
	noPluginText := fmt.Sprintf("bindAddr = \"127.0.0.1\"\nbindPort = %d\nproxyBindAddr = \"127.0.0.1\"\ntransport.tcpMux = false\ntransport.tls.force = true\nauth.method = \"oidc\"\nauth.oidc.issuer = %q\nauth.oidc.audience = %q\n", noPluginPort, oidcHTTP.URL, audience)
	if err := os.WriteFile(noPluginConfig, []byte(noPluginText), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(frps, "verify", "-c", noPluginConfig).Run(); err != nil {
		t.Fatalf("FRPS without plugin config verification failed: %v", err)
	}
	start(frps, noPluginConfig)
	if !waitTCP("127.0.0.1", noPluginPort, 5*time.Second) {
		t.Fatal("no-plugin FRPS listener did not start")
	}
	noPluginClientConfig := filepath.Join(dir, "frpc-no-plugin.toml")
	noPluginClientText := strings.Replace(clientText, fmt.Sprintf("serverPort = %d", control), fmt.Sprintf("serverPort = %d", noPluginPort), 1)
	noPluginClientText = strings.Replace(noPluginClientText, "auth.oidc.clientSecret = \""+credential+"\"", "auth.oidc.clientSecret = \"invalid-device-secret\"", 1)
	if err := os.WriteFile(noPluginClientConfig, []byte(noPluginClientText), 0600); err != nil {
		t.Fatal(err)
	}
	failedLoginCtx, cancelFailedLogin := context.WithTimeout(context.Background(), 5*time.Second)
	loginStarted := time.Now()
	failedLoginOutput, failedLoginErr := exec.CommandContext(failedLoginCtx, frpc, "-c", noPluginClientConfig).CombinedOutput()
	cancelFailedLogin()
	if failedLoginErr == nil || time.Since(loginStarted) >= 4*time.Second {
		t.Fatalf("FRPC unexpectedly authenticated with an invalid device OIDC credential: err=%v output=%s", failedLoginErr, failedLoginOutput)
	}

	start(frps, serverConfig)
	if !waitTCP("127.0.0.1", control, 5*time.Second) {
		t.Fatal("local FRPS control listener did not start")
	}
	badConfig := filepath.Join(dir, "frpc-bad.toml")
	badMetadata := strings.Replace(clientText, "metadatas.rescue_key = \""+credential+"\"", "metadatas.rescue_key = \""+strings.Repeat("b", 64)+"\"", 1)
	if err := os.WriteFile(badConfig, []byte(badMetadata), 0600); err != nil {
		t.Fatal(err)
	}
	badContext, cancelBad := context.WithTimeout(context.Background(), 5*time.Second)
	badOutput, badErr := exec.CommandContext(badContext, frpc, "-c", badConfig).CombinedOutput()
	cancelBad()
	if badErr == nil || !strings.Contains(string(badOutput), "rescue authorization denied") {
		t.Fatalf("bad credential was not explicitly rejected by the FRP plugin: %v", badErr)
	}
	start(frpc, clientConfig)
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(remote)), 300*time.Millisecond)
		if err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			line, readErr := bufio.NewReader(conn).ReadString('\n')
			_ = conn.Close()
			if readErr == nil && line == "SSH-2.0-ty-test\r\n" {
				observedMu.Lock()
				for _, op := range []string{"Login", "NewProxy", "NewWorkConn", "NewUserConn"} {
					if observed[op] == 0 {
						t.Errorf("FRP 0.71.0 did not call %s hook", op)
					}
				}
				observedMu.Unlock()
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	observedMu.Lock()
	observedOps := make(map[string]int, len(observed))
	for op, count := range observed {
		observedOps[op] = count
	}
	observedMu.Unlock()
	t.Fatalf("FRP 0.71.0 did not forward the local SSH greeting through the authorized port; plugin_ops=%v", observedOps)
}

func freeLocalPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}

func waitTCP(host string, port int, duration time.Duration) bool {
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprint(port)), 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}
