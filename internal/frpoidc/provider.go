package frpoidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const tokenLifetime = 5 * time.Minute

type Provider struct {
	Issuer       string
	Audience     string
	Key          *ecdsa.PrivateKey
	VerifyClient func(context.Context, string, string) (string, error)
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer": p.Issuer, "jwks_uri": p.Issuer + "/jwks", "token_endpoint": p.Issuer + "/token",
			"response_types_supported": []string{}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	case "/jwks":
		if r.Method != http.MethodGet || p.Key == nil {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		x, y := p.Key.PublicKey.X, p.Key.PublicKey.Y
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": p.keyID(),
			"x": base64.RawURLEncoding.EncodeToString(x.FillBytes(make([]byte, 32))),
			"y": base64.RawURLEncoding.EncodeToString(y.FillBytes(make([]byte, 32))),
		}}})
	case "/token":
		p.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || p.Key == nil || p.VerifyClient == nil {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "client_credentials" {
		oauthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID, clientSecret = r.Form.Get("client_id"), r.Form.Get("client_secret")
	}
	if clientID == "" || clientSecret == "" || (r.Form.Get("audience") != "" && r.Form.Get("audience") != p.Audience) {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	subject, err := p.VerifyClient(r.Context(), clientID, clientSecret)
	if err != nil || subject == "" || subject != clientID {
		oauthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": p.Issuer, "sub": subject, "aud": p.Audience,
		"iat": now.Unix(), "exp": now.Add(tokenLifetime).Unix(),
	}
	token, err := p.sign(claims)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(tokenLifetime.Seconds()), "scope": "frp"})
}

func (p *Provider) sign(claims map[string]any) (string, error) {
	if p.Key == nil {
		return "", errors.New("OIDC signing key unavailable")
	}
	encode := func(v any) ([]byte, error) { return json.Marshal(v) }
	header, err := encode(map[string]string{"alg": "ES256", "typ": "JWT", "kid": p.keyID()})
	if err != nil {
		return "", err
	}
	body, err := encode(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	hash := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, p.Key, hash[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (p *Provider) keyID() string {
	if p.Key == nil {
		return ""
	}
	public := elliptic.Marshal(elliptic.P256(), p.Key.X, p.Key.Y)
	sum := sha256.Sum256(public)
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

func LoadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("OIDC signing key path is empty")
	}
	data, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, statErr
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("OIDC signing key permissions must not allow group or other access")
		}
		return parsePrivateKey(data)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	data = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if os.IsExist(err) {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		return parsePrivateKey(data)
	}
	if err != nil {
		return nil, err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err = f.Close(); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return key, nil
}

func parsePrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("OIDC signing key is not PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr != nil {
			return nil, fmt.Errorf("invalid OIDC signing key: %w", err)
		}
		return key, nil
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("OIDC signing key must be ECDSA P-256")
	}
	return key, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func oauthError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
