package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var ErrUnauthorized = errors.New("unauthorized")
var ErrReplay = errors.New("replay detected")

type NonceCache struct {
	mu     sync.Mutex
	items  map[string]time.Time
	maxAge time.Duration
}

func NewNonceCache(maxAge time.Duration) *NonceCache {
	return &NonceCache{items: make(map[string]time.Time), maxAge: maxAge}
}

func (c *NonceCache) Use(deviceID, nonce string, now time.Time) bool {
	key := deviceID + ":" + nonce
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, t := range c.items {
		if now.Sub(t) > c.maxAge {
			delete(c.items, k)
		}
	}
	if _, exists := c.items[key]; exists {
		return false
	}
	if len(c.items) >= 100000 {
		return false
	}
	c.items[key] = now
	return true
}

func SecretHash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func VerifySecret(secret, expectedHash string) bool {
	got := SecretHash(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(expectedHash)) == 1
}

func Sign(method, path string, body []byte, timestamp int64, nonce, secret string) string {
	bodyHash := sha256.Sum256(body)
	message := fmt.Sprintf("%s\n%s\n%d\n%s\n%s", strings.ToUpper(method), path, timestamp, nonce, hex.EncodeToString(bodyHash[:]))
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func VerifyRequest(r *http.Request, body []byte, secret string, now time.Time, cache *NonceCache, maxSkew time.Duration) error {
	deviceID := strings.TrimSpace(r.Header.Get("X-TY-Device"))
	nonce := strings.TrimSpace(r.Header.Get("X-TY-Nonce"))
	signature := strings.TrimSpace(r.Header.Get("X-TY-Signature"))
	tsText := strings.TrimSpace(r.Header.Get("X-TY-Timestamp"))
	if deviceID == "" || nonce == "" || len(nonce) > 128 || len(signature) != 64 || tsText == "" {
		return ErrUnauthorized
	}
	ts, err := strconv.ParseInt(tsText, 10, 64)
	if err != nil || ts < now.Add(-maxSkew).Unix() || ts > now.Add(maxSkew).Unix() {
		return ErrUnauthorized
	}
	expected := Sign(r.Method, r.URL.Path, body, ts, nonce, secret)
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(signature)), []byte(expected)) != 1 {
		return ErrUnauthorized
	}
	if cache != nil && !cache.Use(deviceID, nonce, now) {
		return ErrReplay
	}
	return nil
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
