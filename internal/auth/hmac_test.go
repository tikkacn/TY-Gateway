package auth

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSignAndReplayProtection(t *testing.T) {
	body := []byte(`{"ok":true}`)
	now := time.Now().UTC()
	nonce := "n-1"
	secret := "secret-hash"
	r := httptest.NewRequest("POST", "http://example.test/api/v1/device/x/heartbeat", nil)
	r.Header.Set("X-TY-Timestamp", fmt.Sprint(now.Unix()))
	r.Header.Set("X-TY-Nonce", nonce)
	r.Header.Set("X-TY-Device", "x")
	r.Header.Set("X-TY-Signature", Sign("POST", r.URL.Path, body, now.Unix(), nonce, secret))
	c := NewNonceCache(time.Minute)
	if err := VerifyRequest(r, body, secret, now, c, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := VerifyRequest(r, body, secret, now, c, time.Minute); err != ErrReplay {
		t.Fatalf("expected replay, got %v", err)
	}
}
