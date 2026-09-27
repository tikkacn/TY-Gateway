package frpauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Credential derives an FRP-only credential from the existing device secret
// hash. Neither the device secret nor its Cloud HMAC key is sent to FRPS.
// The device can compute the same value from SHA-256(deviceSecret).
func Credential(deviceSecretHash, deviceID string, port int) (string, error) {
	key, err := hex.DecodeString(deviceSecretHash)
	if err != nil || len(key) != sha256.Size || deviceID == "" || port < 1 || port > 65535 {
		return "", errors.New("invalid FRP credential input")
	}
	h := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(h, "tygateway-frp-v1\n%s\n%d", deviceID, port)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func CredentialHash(credential string) string {
	h := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(h[:])
}

type Entry struct {
	DeviceID       string `json:"device_id"`
	Port           int    `json:"port"`
	CredentialHash string `json:"credential_hash"`
}

type Roster struct {
	GeneratedAt time.Time `json:"generated_at"`
	Entries     []Entry   `json:"entries"`
}

func (r Roster) Validate(now time.Time, maxAge time.Duration, minPort, maxPort int) error {
	if maxAge <= 0 || minPort < 1 || maxPort > 65535 || minPort > maxPort || r.GeneratedAt.IsZero() || r.GeneratedAt.After(now.Add(5*time.Minute)) || now.Sub(r.GeneratedAt) > maxAge {
		return errors.New("FRP roster is stale or invalid")
	}
	if len(r.Entries) > 1000 {
		return errors.New("FRP roster is too large")
	}
	ids := make(map[string]bool, len(r.Entries))
	ports := make(map[int]bool, len(r.Entries))
	for _, e := range r.Entries {
		b, err := hex.DecodeString(e.CredentialHash)
		if e.DeviceID == "" || len(e.DeviceID) > 128 || strings.ContainsAny(e.DeviceID, ".:/\\\r\n\t ") || e.Port < minPort || e.Port > maxPort || err != nil || len(b) != sha256.Size || ids[e.DeviceID] || ports[e.Port] {
			return errors.New("FRP roster contains an invalid or duplicate entry")
		}
		ids[e.DeviceID], ports[e.Port] = true, true
	}
	return nil
}

func (r Roster) Authorize(deviceID, credential string) (Entry, bool) {
	if len(credential) != sha256.Size*2 {
		return Entry{}, false
	}
	got := CredentialHash(credential)
	for _, e := range r.Entries {
		if e.DeviceID == deviceID && subtle.ConstantTimeCompare([]byte(got), []byte(e.CredentialHash)) == 1 {
			return e, true
		}
	}
	return Entry{}, false
}
