package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
)

func TestDeviceValidatedNodeInventoryReplacesStalePickerAndRejectsRebind(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemoryStore()
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, secret, err := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:07:01"})
	if err != nil {
		t.Fatal(err)
	}
	sub, err := st.CreateSubscription(ctx, "test", "v2board", []byte("encrypted-private-url"))
	if err != nil {
		t.Fatal(err)
	}
	if err = st.BindSubscription(ctx, d.ID, sub.ID); err != nil {
		t.Fatal(err)
	}
	if err = st.ReplaceSubscriptionNodes(ctx, sub.ID, []model.Node{{ID: "stale", Name: "stale-ipv6", Protocol: "vmess", Server: "secret.invalid"}}); err != nil {
		t.Fatal(err)
	}
	report := func(body []byte) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, signedRequest(http.MethodPost, "/api/v1/device/"+d.ID+"/nodes", body, d.ID, auth.SecretHash(secret)))
		return w
	}
	body, _ := json.Marshal(map[string]any{"subscription_id": sub.ID, "nodes": []model.CustomerNode{{ID: "0000000000000001", Name: "新加坡"}, {ID: "0000000000000002", Name: "日本"}}})
	if w := report(body); w.Code != http.StatusOK {
		t.Fatalf("validated inventory rejected: %d %s", w.Code, w.Body.String())
	}
	nodes, err := st.GetSubscriptionNodes(ctx, sub.ID)
	if err != nil || len(nodes) != 2 || nodes[0].Name != "新加坡" || nodes[0].Server != "" {
		t.Fatalf("safe inventory was not committed: %#v %v", nodes, err)
	}
	subscriptions, err := st.ListSubscriptions(ctx)
	if err != nil || len(subscriptions) != 1 || subscriptions[0].NodeCount != len(nodes) || subscriptions[0].Status != "ok" {
		t.Fatalf("Cloud count diverged from validated picker inventory: %#v %v", subscriptions, err)
	}
	updated, err := st.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if w := report(body); w.Code != http.StatusOK {
		t.Fatalf("idempotent inventory rejected: %d", w.Code)
	}
	again, _ := st.GetDevice(ctx, d.ID)
	if again.ConfigVersion != updated.ConfigVersion {
		t.Fatal("identical inventory unexpectedly changed the config version")
	}
	bad, _ := json.Marshal(map[string]any{"subscription_id": sub.ID, "nodes": []model.CustomerNode{{ID: "0000000000000003", Name: "HK-IPV6"}}})
	if w := report(bad); w.Code != http.StatusBadRequest {
		t.Fatalf("IPv6-labelled node accepted: %d", w.Code)
	}
	next, err := st.CreateSubscription(ctx, "next", "v2board", []byte("different-private-url"))
	if err != nil {
		t.Fatal(err)
	}
	if err = st.BindSubscription(ctx, d.ID, next.ID); err != nil {
		t.Fatal(err)
	}
	if w := report(body); w.Code != http.StatusConflict {
		t.Fatalf("stale subscription report accepted: %d", w.Code)
	}
	unauthorized := httptest.NewRecorder()
	srv.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/device/"+d.ID+"/nodes", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned inventory accepted: %d", unauthorized.Code)
	}
}
