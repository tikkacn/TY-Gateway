package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"tygateway/internal/auth"
	"tygateway/internal/model"
	"tygateway/internal/store"
	"tygateway/internal/subscription"
)

func TestIdentityUniquenessLookupAndPrivateNotes(t *testing.T) {
	st := store.NewMemoryStore()
	ctx := context.Background()
	srv := NewServer(st, "admin", []byte("0123456789abcdef0123456789abcdef"))
	d, secret, _ := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:01"})
	other, _, _ := st.RegisterDevice(ctx, model.RegisterDeviceInput{MAC: "02:00:00:00:00:02"})
	st.UpdateDevice(ctx, d.ID, "pending", "private-admin-note", "gfw_precise")
	cipher, err := subscription.EncryptURL("https://example.invalid/sub?token=dummy-only", srv.SubscriptionKey)
	if err != nil {
		t.Fatal(err)
	}
	const rawSubscriptionURL = "https://example.invalid/sub?token=dummy-only"
	sub, _ := st.CreateSubscription(ctx, "test", "test", cipher, lookupDigest(rawSubscriptionURL, srv.SubscriptionKey))
	if _, err := st.CreateSubscription(ctx, "duplicate", "test", nil, lookupDigest(rawSubscriptionURL, srv.SubscriptionKey)); err != store.ErrConflict {
		t.Fatal("duplicate URL accepted")
	}
	if _, err := st.UpdateIdentity(ctx, d.ID, "Living room", " Person@Example.com ", sub.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpdateIdentity(ctx, other.ID, "other", "person@example.com", ""); err != store.ErrConflict {
		t.Fatal("duplicate email accepted")
	}
	if _, err := st.UpdateIdentity(ctx, other.ID, "other", "other@example.com", sub.ID); err != store.ErrConflict {
		t.Fatal("shared subscription accepted")
	}
	for _, route := range []string{"config", "heartbeat", "status"} {
		method := "GET"
		var body []byte
		if route != "config" {
			method = "POST"
			body = []byte(`{"status":"ok"}`)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, signedRequest(method, "/api/v1/device/"+d.ID+"/"+route, body, d.ID, auth.SecretHash(secret)))
		if w.Code != 200 {
			t.Fatalf("%s: %d", route, w.Code)
		}
		for _, private := range []string{"private-admin-note", "person@example.com", `"note"`, `"email"`, `"subscription_id"`} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("private data in device response")
			}
		}
		if !strings.Contains(w.Body.String(), "Living room") || !strings.Contains(w.Body.String(), d.Serial) {
			t.Fatal("customer identity missing")
		}
	}
	for _, q := range []string{`{"kind":"email","value":"PERSON@example.com"}`, `{"kind":"serial","value":"020000000001"}`, `{"kind":"subscription","value":"https://example.invalid/sub?token=dummy-only"}`} {
		r := httptest.NewRequest("POST", "/api/v1/admin/devices/lookup", strings.NewReader(q))
		r.Header.Set("X-TY-Admin-Token", "admin")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "private-admin-note") {
			t.Fatal("admin lookup missing note")
		}
		if strings.Contains(w.Body.String(), "dummy-only") {
			t.Fatal("lookup echoed subscription credential")
		}
	}
	revealBody, _ := json.Marshal(map[string]string{"id": sub.ID})
	revealReq := httptest.NewRequest("POST", "/api/v1/admin/subscriptions/reveal", bytes.NewReader(revealBody))
	revealReq.Header.Set("X-TY-Admin-Token", "admin")
	reveal := httptest.NewRecorder()
	srv.ServeHTTP(reveal, revealReq)
	if reveal.Code != 200 || !strings.Contains(reveal.Body.String(), "https://example.invalid/sub?token=dummy-only") {
		t.Fatal("explicit admin reveal failed")
	}
	unauthReveal := httptest.NewRecorder()
	srv.ServeHTTP(unauthReveal, httptest.NewRequest("POST", "/api/v1/admin/subscriptions/reveal", bytes.NewReader(revealBody)))
	if unauthReveal.Code != 401 {
		t.Fatal("unauthorized subscription reveal accepted")
	}
	payload, _ := json.Marshal(map[string]string{"id": d.ID, "email": "changed@example.com"})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/admin/devices/identity", bytes.NewReader(payload)))
	if w.Code != 401 {
		t.Fatal("unauthorized binding accepted")
	}
}
