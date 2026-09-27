package customer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidSession = errors.New("invalid customer session")

const SessionLifetime = 8 * time.Hour

func SessionKey(subscriptionKey []byte) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte("customer-session-v1\x00"))
	_, _ = h.Write(subscriptionKey)
	return h.Sum(nil)
}

func NewSession(deviceID string, version int64, now time.Time, key []byte) string {
	expires := now.Add(SessionLifetime).Unix()
	payload := "v2." + deviceID + "." + strconv.FormatInt(version, 10) + "." + strconv.FormatInt(expires, 10)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + sign(payload, key)))
}

func VerifySession(token string, now time.Time, key []byte) (string, int64, error) {
	if len(token) > 512 {
		return "", 0, ErrInvalidSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return "", 0, ErrInvalidSession
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 5 || parts[0] != "v2" || len(parts[1]) != 32 || len(parts[4]) != 64 {
		return "", 0, ErrInvalidSession
	}
	version, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || version < 0 {
		return "", 0, ErrInvalidSession
	}
	expires, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil || expires <= now.Unix() || expires > now.Add(SessionLifetime).Unix() {
		return "", 0, ErrInvalidSession
	}
	payload := strings.Join(parts[:4], ".")
	expected := sign(payload, key)
	if !hmac.Equal([]byte(parts[4]), []byte(expected)) {
		return "", 0, ErrInvalidSession
	}
	return parts[1], version, nil
}

func sign(payload string, key []byte) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}
