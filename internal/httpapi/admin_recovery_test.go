package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tygateway/internal/model"
	"tygateway/internal/recovery"
	"tygateway/internal/store"
)

func TestAdminIssuesOfflineDeviceBoundRecoveryAuthorization(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	d, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:10:01"})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "test-admin", []byte("0123456789abcdef0123456789abcdef"))
	srv.RecoverySigningKey = privateKey
	srv.RecoveryKeyID = "support-test"
	challenge, err := recovery.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"device_code": d.Serial, "challenge": challenge})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/recovery/issue", bytes.NewReader(body))
	request.Header.Set("X-TY-Admin-Token", "test-admin")
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("issue status=%d body=%s", response.Code, response.Body.String())
	}
	var issued struct {
		DeviceCode    string    `json:"device_code"`
		Purpose       string    `json:"purpose"`
		Authorization string    `json:"authorization"`
		IssuedAt      time.Time `json:"issued_at"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.DeviceCode != d.Serial || issued.Purpose != recovery.Purpose || issued.Authorization == "" || issued.ExpiresAt.IsZero() || !issued.ExpiresAt.After(issued.IssuedAt) {
		t.Fatalf("incomplete recovery response: %+v", issued)
	}
	if issued.ExpiresAt.Sub(issued.IssuedAt) != recovery.TicketLifetime {
		t.Fatalf("unexpected recovery lifetime: %s", issued.ExpiresAt.Sub(issued.IssuedAt))
	}
	if _, err := recovery.Verify(map[string]ed25519.PublicKey{"support-test": publicKey}, issued.Authorization, d.Serial, challenge); err != nil {
		t.Fatalf("device-side verification failed: %v", err)
	}
	for _, forbidden := range []string{"subscription", "email", "note", "private key"} {
		if strings.Contains(strings.ToLower(response.Body.String()), forbidden) {
			t.Fatalf("recovery response leaked unrelated data %q", forbidden)
		}
	}
}

func TestRecoveryIssuanceIsAdminOnlyAndRequiresConfiguredSigner(t *testing.T) {
	st := store.NewMemoryStore()
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:10:02"})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := recovery.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"device_code": d.Serial, "challenge": challenge})
	srv := NewServer(st, "test-admin", []byte("0123456789abcdef0123456789abcdef"))

	unauthorized := httptest.NewRecorder()
	srv.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/admin/recovery/issue", bytes.NewReader(body)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized issue status=%d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/recovery/issue", bytes.NewReader(body))
	request.Header.Set("X-TY-Admin-Token", "test-admin")
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured signer status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRecoveryIssuanceRejectsBadChallenge(t *testing.T) {
	st := store.NewMemoryStore()
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:10:03"})
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(st, "test-admin", []byte("0123456789abcdef0123456789abcdef"))
	srv.RecoverySigningKey, srv.RecoveryKeyID = privateKey, "support-test"
	body := []byte(`{"device_code":"` + d.Serial + `","challenge":"MAC"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/recovery/issue", bytes.NewReader(body))
	request.Header.Set("X-TY-Admin-Token", "test-admin")
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid challenge status=%d body=%s", response.Code, response.Body.String())
	}
}
