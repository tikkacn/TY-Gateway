package httpapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/frpauth"
	"tygateway/internal/frpoidc"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestFRPOIDCTokenRequiresClaimedEnabledMACDevice(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	srv.RequireActivation = true
	srv.LegacyFRPRetired = true
	srv.AutoFRP = testOIDCAutoFRP("127.0.0.1")
	srv.AutoFRPPortStart, srv.AutoFRPPortEnd = 22000, 22999

	prepare := httptest.NewRequest(http.MethodPost, "/api/v1/admin/enrollments", strings.NewReader(`{"mac":"02:00:00:00:70:44","note":"oidc-test"}`))
	prepare.Header.Set("X-TY-Admin-Token", "admin-test")
	prepared := httptest.NewRecorder()
	srv.ServeHTTP(prepared, prepare)
	if prepared.Code != http.StatusCreated {
		t.Fatalf("prepare MAC: %d %s", prepared.Code, prepared.Body.String())
	}
	const deviceSecret = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	register := httptest.NewRequest(http.MethodPost, "/api/v1/devices/register", strings.NewReader(`{"mac":"020000007044","device_secret":"`+deviceSecret+`"}`))
	registered := httptest.NewRecorder()
	srv.ServeHTTP(registered, register)
	if registered.Code != http.StatusCreated {
		t.Fatalf("MAC claim: %d %s", registered.Code, registered.Body.String())
	}
	var claim struct {
		Device struct {
			ID string `json:"id"`
		} `json:"device"`
	}
	if err := json.Unmarshal(registered.Body.Bytes(), &claim); err != nil || claim.Device.ID == "" {
		t.Fatalf("invalid claim response: %v", err)
	}
	if err := st.SetRescueSSHPort(ctx, claim.Device.ID, 22000); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer := srv.AutoFRP.OIDCIssuer
	srv.FRPOIDC = &frpoidc.Provider{Issuer: issuer, Audience: srv.AutoFRP.OIDCAudience, Key: key, VerifyClient: srv.VerifyFRPOIDCClient}
	credential, err := frpauth.Credential(auth.SecretHash(deviceSecret), claim.Device.ID, 22000)
	if err != nil {
		t.Fatal(err)
	}

	issue := func(secret string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}, "audience": {srv.AutoFRP.OIDCAudience}, "scope": {"frp"}}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/frp/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(claim.Device.ID, secret)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	valid := issue(credential)
	if valid.Code != http.StatusOK || !strings.Contains(valid.Body.String(), `"access_token"`) {
		t.Fatalf("approved MAC device did not receive an OIDC token: %d %s", valid.Code, valid.Body.String())
	}
	if got := issue(strings.Repeat("0", 64)); got.Code != http.StatusUnauthorized {
		t.Fatalf("wrong device credential status=%d, want 401", got.Code)
	}
	if _, err := st.UpdateDevice(ctx, claim.Device.ID, model.DeviceDisabled, "disabled", ""); err != nil {
		t.Fatal(err)
	}
	if got := issue(credential); got.Code != http.StatusUnauthorized {
		t.Fatalf("disabled device retained FRP token access: %d %s", got.Code, got.Body.String())
	}
	d, err := st.GetDevice(ctx, claim.Device.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DeactivateDevice(ctx, d.ID, d.ConfigVersion, d.MAC); err != nil {
		t.Fatal(err)
	}
	if got := issue(credential); got.Code != http.StatusUnauthorized {
		t.Fatalf("deactivated identity retained OIDC access: %d", got.Code)
	}
}
