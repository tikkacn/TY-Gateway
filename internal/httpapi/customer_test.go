package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestCustomerPortalIsolationAndOperations(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:11"})
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := st.CreateSubscription(ctx, "private-plan-name", "v2board", []byte("private-subscription-url"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceSubscriptionNodes(ctx, subscription.ID, []model.Node{
		{ID: "node-1", Name: "Customer-safe node label", Protocol: "tuic", Server: "secret-node.example", Port: 443, Params: map[string]string{"password": "private-node-credential"}},
		{ID: "node-ipv6", Name: "GCC-HK-IPV6", Protocol: "vless", Server: "v6.example", Port: 443},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpdateDevice(ctx, d.ID, "enabled", "private admin note", "gfw_precise"); err != nil {
		t.Fatal(err)
	}
	if _, err = st.UpdateIdentity(ctx, d.ID, "Living room", "user@example.com", subscription.ID); err != nil {
		t.Fatal(err)
	}
	accessReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/devices/customer-access", strings.NewReader(`{"id":"`+d.ID+`"}`))
	accessReq.Header.Set("X-TY-Admin-Token", "admin")
	accessResp := httptest.NewRecorder()
	srv.ServeHTTP(accessResp, accessReq)
	if accessResp.Code != http.StatusOK {
		t.Fatalf("access status=%d body=%s", accessResp.Code, accessResp.Body.String())
	}
	var issued struct {
		Token string `json:"access_token"`
	}
	if err := json.Unmarshal(accessResp.Body.Bytes(), &issued); err != nil || issued.Token == "" {
		t.Fatal("customer access token was not issued")
	}
	loginBody, _ := json.Marshal(map[string]string{"device_code": d.Serial, "access_token": issued.Token})
	loginResp := httptest.NewRecorder()
	srv.ServeHTTP(loginResp, httptest.NewRequest(http.MethodPost, "/api/v1/customer/login", bytes.NewReader(loginBody)))
	if loginResp.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginResp.Code, loginResp.Body.String())
	}
	var logged struct {
		Session string `json:"session_token"`
	}
	if err := json.Unmarshal(loginResp.Body.Bytes(), &logged); err != nil || logged.Session == "" {
		t.Fatal("customer session was not issued")
	}
	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/customer/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+logged.Session)
	meResp := httptest.NewRecorder()
	srv.ServeHTTP(meResp, meReq)
	if meResp.Code != http.StatusOK {
		t.Fatalf("me status=%d body=%s", meResp.Code, meResp.Body.String())
	}
	for _, private := range []string{"private admin note", "user@example.com", `"subscription_id"`, `"note"`, "private-plan-name", "private-subscription-url", "secret-node.example", "private-node-credential", `"server"`, `"port"`, `"params"`} {
		if strings.Contains(meResp.Body.String(), private) {
			t.Fatalf("customer response leaked %s", private)
		}
	}
	if !strings.Contains(meResp.Body.String(), d.Serial) || !strings.Contains(meResp.Body.String(), "Living room") || !strings.Contains(meResp.Body.String(), "Customer-safe node label") || strings.Contains(meResp.Body.String(), "GCC-HK-IPV6") {
		t.Fatal("customer response has incorrect identity or IPv6-marked node list")
	}
	_, _, configNodes, _, err := srv.policySnapshot(ctx, d.ID)
	if err != nil || len(configNodes) != 1 || configNodes[0].ID != "node-1" {
		t.Fatalf("device policy node list did not match the filtered customer list: nodes=%#v err=%v", configNodes, err)
	}
	filteredPreference := httptest.NewRecorder()
	filteredPreferenceReq := httptest.NewRequest(http.MethodPost, "/api/v1/customer/node-preference", strings.NewReader(`{"category":"AI","node_id":"node-ipv6"}`))
	filteredPreferenceReq.Header.Set("Authorization", "Bearer "+logged.Session)
	srv.ServeHTTP(filteredPreference, filteredPreferenceReq)
	if filteredPreference.Code != http.StatusNotFound {
		t.Fatalf("IPv6-marked node preference status=%d body=%s", filteredPreference.Code, filteredPreference.Body.String())
	}
	beforePreference, err := st.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	validPreference := httptest.NewRecorder()
	validPreferenceReq := httptest.NewRequest(http.MethodPost, "/api/v1/customer/node-preference", strings.NewReader(`{"category":"AI","node_id":"node-1"}`))
	validPreferenceReq.Header.Set("Authorization", "Bearer "+logged.Session)
	srv.ServeHTTP(validPreference, validPreferenceReq)
	var savedPreference struct {
		ConfigVersion int64             `json:"config_version"`
		Preferences   map[string]string `json:"preferences"`
	}
	if validPreference.Code != http.StatusOK || json.Unmarshal(validPreference.Body.Bytes(), &savedPreference) != nil || savedPreference.ConfigVersion != beforePreference.ConfigVersion+1 || savedPreference.Preferences["AI"] != "node-1" {
		t.Fatalf("node preference was not saved with a confirmation version: status=%d body=%s", validPreference.Code, validPreference.Body.String())
	}

	newRule := httptest.NewRecorder()
	ruleReq := httptest.NewRequest(http.MethodPost, "/api/v1/customer/rules", strings.NewReader(`{"match_type":"domain_suffix","match_value":"example.com","action":"DIRECT"}`))
	ruleReq.Header.Set("Authorization", "Bearer "+logged.Session)
	srv.ServeHTTP(newRule, ruleReq)
	if newRule.Code != http.StatusCreated || !strings.Contains(newRule.Body.String(), "example.com") {
		t.Fatalf("customer rule status=%d body=%s", newRule.Code, newRule.Body.String())
	}
	override := httptest.NewRecorder()
	overrideReq := httptest.NewRequest(http.MethodPost, "/api/v1/customer/override", strings.NewReader(`{"action":"PROXY","duration_minutes":30}`))
	overrideReq.Header.Set("Authorization", "Bearer "+logged.Session)
	srv.ServeHTTP(override, overrideReq)
	if override.Code != http.StatusOK || !strings.Contains(override.Body.String(), "PROXY") {
		t.Fatalf("customer override status=%d body=%s", override.Code, override.Body.String())
	}

	adminAttempt := httptest.NewRecorder()
	adminReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/devices", nil)
	adminReq.Header.Set("Authorization", "Bearer "+logged.Session)
	srv.ServeHTTP(adminAttempt, adminReq)
	if adminAttempt.Code != http.StatusUnauthorized {
		t.Fatal("customer session crossed into admin API")
	}
}

func TestTemporaryOverrideSixHourLimitAndCancel(t *testing.T) {
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, _, err := st.RegisterDevice(context.Background(), model.RegisterDeviceInput{MAC: "02:00:00:00:00:12"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"action":"PROXY","duration_minutes":5}`, 200},
		{`{"action":"DIRECT","duration_minutes":360}`, 200},
		{`{"action":"PROXY","duration_minutes":361}`, 400},
		{`{"action":"PROXY","duration_minutes":10080}`, 400},
		{`{"action":"","duration_minutes":0}`, 200},
	} {
		w := httptest.NewRecorder()
		srv.setCustomerOverride(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body)), d)
		if w.Code != tc.code {
			t.Fatalf("%s: status %d", tc.body, w.Code)
		}
		if tc.body == `{"action":"","duration_minutes":0}` {
			var result struct {
				Device model.Device `json:"device"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Device.CustomerOverrideAction != "" || result.Device.CustomerOverrideUntil != nil {
				t.Fatal("cancel did not clear override")
			}
		}
	}
}

func TestCustomerPortalClearlyStatesItsRestrictedScope(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "admin", []byte("0123456789abcdef0123456789abcdef"))
	request := httptest.NewRequest(http.MethodGet, "/portal", nil)
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("portal status=%d", response.Code)
	}
	for _, required := range []string{"订阅地址、账户信息、管理员备注及完整节点凭据由服务商管理", "规则集节点", "临时代理模式"} {
		if !strings.Contains(response.Body.String(), required) {
			t.Fatalf("customer portal is missing scope text %q", required)
		}
	}
}

func TestDeviceSignedCustomerBridgeIsScopedAndSecretFree(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, secret, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:12"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateIdentity(ctx, d.ID, "Local device", "hidden@example.invalid", ""); err != nil {
		t.Fatal(err)
	}
	key := auth.SecretHash(secret)
	me := httptest.NewRecorder()
	srv.ServeHTTP(me, signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/customer/me", nil, d.ID, key))
	if me.Code != http.StatusOK || !strings.Contains(me.Body.String(), d.Serial) || strings.Contains(me.Body.String(), "hidden@example.invalid") {
		t.Fatalf("device customer state status=%d body=%s", me.Code, me.Body.String())
	}
	ruleBody := []byte(`{"match_type":"domain_suffix","match_value":"example.org","action":"DIRECT"}`)
	rule := httptest.NewRecorder()
	srv.ServeHTTP(rule, signedRequest(http.MethodPost, "/api/v1/device/"+d.ID+"/customer/rules", ruleBody, d.ID, key))
	if rule.Code != http.StatusCreated || !strings.Contains(rule.Body.String(), "example.org") {
		t.Fatalf("device customer rule status=%d body=%s", rule.Code, rule.Body.String())
	}
	unauthorized := httptest.NewRecorder()
	srv.ServeHTTP(unauthorized, signedRequest(http.MethodGet, "/api/v1/device/"+d.ID+"/customer/me", nil, d.ID, auth.SecretHash("wrong")))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("wrong device secret accepted: %d", unauthorized.Code)
	}
}
