package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestDeleteSubscriptionRemovesCloudRecordAndUnbindsDevice(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin-test-token", []byte("0123456789abcdef0123456789abcdef"))
	device, deviceSecret, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:91"})
	if err != nil {
		t.Fatal(err)
	}

	const rawURL = "https://provider.example.invalid/sub?token=delete-test-secret"
	admin := func(path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("X-TY-Admin-Token", "admin-test-token")
		resp := httptest.NewRecorder()
		srv.ServeHTTP(resp, req)
		return resp
	}
	created := admin("/api/v1/admin/subscriptions", []byte(`{"name":"wrong-plan","provider":"v2board","url":"`+rawURL+`"}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", created.Code, created.Body.String())
	}
	var subscriptionResult struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &subscriptionResult); err != nil || subscriptionResult.ID == "" {
		t.Fatalf("create response invalid: %v", err)
	}
	identityBody, _ := json.Marshal(map[string]string{
		"id": device.ID, "name": "test-device", "email": "person@example.invalid", "subscription_id": subscriptionResult.ID,
	})
	if bound := admin("/api/v1/admin/devices/identity", identityBody); bound.Code != http.StatusOK {
		t.Fatalf("bind status=%d body=%s", bound.Code, bound.Body.String())
	}
	if err := st.ReplaceSubscriptionNodes(ctx, subscriptionResult.ID, []model.Node{{ID: "node-one", Name: "Test node", Protocol: "test", Server: "node.example.invalid", Group: "AUTO"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetCustomerNodePreference(ctx, device.ID, "AUTO", "node-one"); err != nil {
		t.Fatal(err)
	}
	before, err := st.GetDevice(ctx, device.ID)
	if err != nil {
		t.Fatal(err)
	}

	deleteBody, _ := json.Marshal(map[string]string{"id": subscriptionResult.ID})
	unauthorized := httptest.NewRecorder()
	srv.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/admin/subscriptions/delete", bytes.NewReader(deleteBody)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized delete status=%d", unauthorized.Code)
	}
	if _, err := st.GetSubscriptionCiphertext(ctx, subscriptionResult.ID); err != nil {
		t.Fatal("unauthorized request changed subscription state")
	}

	deleted := admin("/api/v1/admin/subscriptions/delete", deleteBody)
	if deleted.Code != http.StatusOK || !strings.Contains(deleted.Body.String(), `"detached_devices":1`) {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
	if strings.Contains(deleted.Body.String(), rawURL) || strings.Contains(deleted.Body.String(), "delete-test-secret") {
		t.Fatal("delete response leaked the subscription URL")
	}
	if _, err := st.GetSubscriptionCiphertext(ctx, subscriptionResult.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("ciphertext still exists after delete: %v", err)
	}
	if _, err := st.FindSubscriptionByLookup(ctx, lookupDigest(rawURL, srv.SubscriptionKey)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("lookup digest still resolves after delete: %v", err)
	}
	if _, err := st.GetSubscriptionNodes(ctx, subscriptionResult.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("subscription nodes still exist after delete: %v", err)
	}
	after, err := st.GetDevice(ctx, device.ID)
	if err != nil || after.SubscriptionID != "" || after.ConfigVersion != before.ConfigVersion+1 || after.Email != "person@example.invalid" {
		t.Fatalf("device binding was not safely cleared: device=%#v err=%v", after, err)
	}
	if prefs, err := st.ListCustomerNodePreferences(ctx, device.ID); err != nil || len(prefs) != 0 {
		t.Fatalf("node preferences remain after delete: %#v err=%v", prefs, err)
	}

	config := httptest.NewRecorder()
	srv.ServeHTTP(config, signedRequest(http.MethodGet, "/api/v1/device/"+device.ID+"/config", nil, device.ID, auth.SecretHash(deviceSecret)))
	if config.Code != http.StatusOK || !strings.Contains(config.Body.String(), `"dae_subscription_managed":true`) || strings.Contains(config.Body.String(), `"dae_subscription":`) {
		t.Fatalf("device did not receive the unbound config: status=%d body=%s", config.Code, config.Body.String())
	}
	if strings.Contains(config.Body.String(), "delete-test-secret") {
		t.Fatal("device config retained the deleted subscription secret")
	}
	staleReport := []byte(`{"status":"ok","dae_subscription_id":"` + subscriptionResult.ID + `","dae_status":"ok","dae_node_count":25}`)
	staleHeartbeat := httptest.NewRecorder()
	srv.ServeHTTP(staleHeartbeat, signedRequest(http.MethodPost, "/api/v1/device/"+device.ID+"/heartbeat", staleReport, device.ID, auth.SecretHash(deviceSecret)))
	if staleHeartbeat.Code != http.StatusOK {
		t.Fatalf("stale pre-delete device report was not ignored: status=%d body=%s", staleHeartbeat.Code, staleHeartbeat.Body.String())
	}
	if second := admin("/api/v1/admin/subscriptions/delete", deleteBody); second.Code != http.StatusNotFound {
		t.Fatalf("second delete status=%d body=%s", second.Code, second.Body.String())
	}
}
