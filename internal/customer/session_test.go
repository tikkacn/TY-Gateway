package customer

import (
	"strings"
	"testing"
	"time"
)

func TestSessionVersionAndIntegrity(t *testing.T) {
	now := time.Now()
	key := []byte("test-key")
	id := strings.Repeat("a", 32)
	token := NewSession(id, 7, now, key)
	got, v, err := VerifySession(token, now, key)
	if err != nil || got != id || v != 7 {
		t.Fatal("session roundtrip failed")
	}
	if _, _, err = VerifySession(token, now.Add(9*time.Hour), key); err == nil {
		t.Fatal("expired session accepted")
	}
	if _, _, err = VerifySession(token, now, []byte("wrong-key")); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, _, err = VerifySession(token+"x", now, key); err == nil {
		t.Fatal("tampering accepted")
	}
}
