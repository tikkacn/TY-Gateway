package recovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func testKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func TestRecoveryAuthorizationBoundToDeviceAndChallenge(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := Sign(privateKey, "support-2026-01", "02:00:00:00:00:01", challenge)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := Verify(map[string]ed25519.PublicKey{"support-2026-01": publicKey}, token, "020000000001", challenge)
	if err != nil || claims.Purpose != Purpose || claims.DeviceCode != "020000000001" || claims.Challenge != challenge {
		t.Fatalf("valid ticket rejected: claims=%+v err=%v", claims, err)
	}
	if _, err := Verify(map[string]ed25519.PublicKey{"support-2026-01": publicKey}, token, "020000000002", challenge); err == nil {
		t.Fatal("ticket was accepted for a different device")
	}
	otherChallenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(map[string]ed25519.PublicKey{"support-2026-01": publicKey}, token, "020000000001", otherChallenge); err == nil {
		t.Fatal("ticket was accepted for a different challenge")
	}
}

func TestRecoveryAuthorizationRejectsTamperingAndUnknownKey(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := Sign(privateKey, "key-a", "020000000001", challenge)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-2] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
	if _, err := Verify(map[string]ed25519.PublicKey{"key-a": publicKey}, tampered, "020000000001", challenge); err == nil {
		t.Fatal("tampered token was accepted")
	}
	if _, err := Verify(map[string]ed25519.PublicKey{"other": publicKey}, token, "020000000001", challenge); err == nil {
		t.Fatal("token with unknown key id was accepted")
	}
}

func TestRecoveryChallengeAndKeyParsing(t *testing.T) {
	challenge, err := NewChallenge()
	if err != nil || !validChallenge(challenge) {
		t.Fatalf("invalid generated challenge %q: %v", challenge, err)
	}
	if validChallenge(challenge[:25] + "0") {
		t.Fatal("invalid Base32 challenge accepted")
	}
	publicKey, privateKey := testKeyPair(t)
	parsedPrivate, err := ParsePrivateKey(base64.RawStdEncoding.EncodeToString(privateKey))
	if err != nil || string(parsedPrivate) != string(privateKey) {
		t.Fatal("base64 private key did not round-trip")
	}
	parsedPublic, err := ParsePublicKey(base64.RawStdEncoding.EncodeToString(publicKey))
	if err != nil || string(parsedPublic) != string(publicKey) {
		t.Fatal("base64 public key did not round-trip")
	}
	if _, err := ParsePrivateKey("too-short"); err == nil {
		t.Fatal("short signing key accepted")
	}
}

func TestRecoveryAuthorizationExpiresAndCannotBeExtended(t *testing.T) {
	publicKey, privateKey := testKeyPair(t)
	challenge, err := NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 9, 22, 3, 4, 5, 0, time.UTC)
	token, claims, err := SignAt(privateKey, "support-expiry", "02:00:00:00:00:09", challenge, issuedAt, TicketLifetime)
	if err != nil {
		t.Fatal(err)
	}
	if claims.IssuedAt != issuedAt.Unix() || claims.ExpiresAt != issuedAt.Add(TicketLifetime).Unix() {
		t.Fatalf("unexpected ticket times: %+v", claims)
	}
	keys := map[string]ed25519.PublicKey{"support-expiry": publicKey}
	if _, err := VerifyAt(keys, token, "020000000009", challenge, issuedAt.Add(TicketLifetime-1*time.Second)); err != nil {
		t.Fatalf("unexpired ticket rejected: %v", err)
	}
	if _, err := VerifyAt(keys, token, "020000000009", challenge, issuedAt.Add(TicketLifetime+TicketClockSkew+1*time.Second)); err == nil {
		t.Fatal("expired ticket was accepted")
	}
	if _, _, err := SignAt(privateKey, "support-expiry", "020000000009", challenge, issuedAt, TicketLifetime+time.Second); err == nil {
		t.Fatal("ticket lifetime was extended beyond the hard cap")
	}
}
