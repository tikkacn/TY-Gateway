package frpoidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProviderDiscoveryAndPerDeviceToken(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var provider *Provider
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { provider.ServeHTTP(w, r) }))
	defer server.Close()
	const audience, clientID, secret = "ty-gateway-frp", "device-42", "device-only-credential"
	provider = &Provider{Issuer: server.URL, Audience: audience, Key: key, VerifyClient: func(_ context.Context, id, got string) (string, error) {
		if id != clientID || got != secret {
			return "", context.Canceled
		}
		return id, nil
	}}

	discovery, err := http.Get(server.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer discovery.Body.Close()
	var metadata map[string]any
	if err := json.NewDecoder(discovery.Body).Decode(&metadata); err != nil || metadata["issuer"] != server.URL || metadata["jwks_uri"] != server.URL+"/jwks" || metadata["token_endpoint"] != server.URL+"/token" {
		t.Fatalf("bad OIDC discovery metadata: %#v %v", metadata, err)
	}

	form := url.Values{"grant_type": {"client_credentials"}, "audience": {audience}, "scope": {"frp"}}
	req, err := http.NewRequest(http.MethodPost, server.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(clientID, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil || response.StatusCode != http.StatusOK || tokenResponse.TokenType != "Bearer" || tokenResponse.ExpiresIn != int(tokenLifetime.Seconds()) {
		t.Fatalf("bad OIDC token response: status=%d token=%#v err=%v", response.StatusCode, tokenResponse, err)
	}
	parts := strings.Split(tokenResponse.AccessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid signed JWT %q", tokenResponse.AccessToken)
	}
	var claims struct {
		Issuer   string `json:"iss"`
		Subject  string `json:"sub"`
		Audience string `json:"aud"`
		Expires  int64  `json:"exp"`
	}
	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(claimBytes, &claims) != nil || claims.Issuer != server.URL || claims.Subject != clientID || claims.Audience != audience || claims.Expires == 0 {
		t.Fatalf("wrong OIDC claims: %#v err=%v", claims, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("invalid ES256 signature encoding: %v", err)
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&key.PublicKey, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("OIDC token signature did not verify")
	}

	badForm := url.Values{"grant_type": {"client_credentials"}, "audience": {audience}}
	badReq, _ := http.NewRequest(http.MethodPost, server.URL+"/token", strings.NewReader(badForm.Encode()))
	badReq.SetBasicAuth(clientID, "wrong-secret")
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badResponse, err := server.Client().Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	defer badResponse.Body.Close()
	if badResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid per-device credential status=%d, want 401", badResponse.StatusCode)
	}
}

func TestLoadOrCreateKeyPersistsPrivateECDSAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "issuer.pem")
	first, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateKey(path)
	if err != nil || first.X.Cmp(second.X) != 0 || first.Y.Cmp(second.Y) != 0 || first.D.Cmp(second.D) != 0 {
		t.Fatalf("OIDC signing key was not stable across restart: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("OIDC key permissions are not private: info=%v err=%v", info, err)
		}
	}
	if err := os.WriteFile(path, []byte("not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("invalid persistent OIDC key was silently replaced")
	}
}
