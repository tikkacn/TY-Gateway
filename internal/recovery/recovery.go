// Package recovery implements one-time, device-bound local password recovery
// authorizations. The OEC holds only the Ed25519 public key and can therefore
// validate a support ticket while completely offline.
package recovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"tygateway/internal/identity"
)

const Purpose = "local-password-reset"

var (
	ErrInvalidChallenge = errors.New("invalid recovery challenge")
	ErrInvalidTicket    = errors.New("invalid recovery authorization")
	ErrInvalidKey       = errors.New("invalid recovery signing key")
	challengePattern    = regexp.MustCompile(`^[A-Z2-7]{26}$`)
	keyIDPattern        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
)

const signatureContext = "TY-GATEWAY-RECOVERY-V1\x00"

type Claims struct {
	Version    int    `json:"v"`
	KeyID      string `json:"kid"`
	DeviceCode string `json:"device_code"`
	Challenge  string `json:"challenge"`
	Purpose    string `json:"purpose"`
	TicketID   string `json:"ticket_id"`
	IssuedAt   int64  `json:"iat"`
	ExpiresAt  int64  `json:"exp"`
}

// NewChallenge returns a 128-bit, human-copyable Base32 challenge. The local
// manager must keep its issue time in memory, expire it after ten minutes, and
// clear it on process restart or successful use.
func NewChallenge() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

func validChallenge(value string) bool {
	if !challengePattern.MatchString(value) {
		return false
	}
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(value)
	return err == nil && len(b) == 16
}

// ValidKeyID reports whether a public-key identifier is safe and canonical.
func ValidKeyID(value string) bool {
	return keyIDPattern.MatchString(value)
}

// Sign issues a token for one exact device and one active local challenge.
// The caller must authenticate the support operator and audit issuance.
func Sign(privateKey ed25519.PrivateKey, keyID, deviceCode, challenge string) (string, Claims, error) {
	return SignAt(privateKey, keyID, deviceCode, challenge, time.Now().UTC(), TicketLifetime)
}

// SignAt is the deterministic-clock form of Sign used by tests and migration
// tooling. Tickets may be shorter-lived than the default, but never longer.
func SignAt(privateKey ed25519.PrivateKey, keyID, deviceCode, challenge string, issuedAt time.Time, lifetime time.Duration) (string, Claims, error) {
	if len(privateKey) != ed25519.PrivateKeySize || !ValidKeyID(keyID) || !validChallenge(challenge) {
		return "", Claims{}, ErrInvalidKey
	}
	if lifetime <= 0 || lifetime > TicketLifetime {
		return "", Claims{}, ErrInvalidTicket
	}
	serial, _, err := identity.NormalizeMAC(deviceCode)
	if err != nil {
		return "", Claims{}, ErrInvalidTicket
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	if issuedAt.IsZero() {
		return "", Claims{}, ErrInvalidTicket
	}
	var ticketID [16]byte
	if _, err := rand.Read(ticketID[:]); err != nil {
		return "", Claims{}, err
	}
	claims := Claims{
		Version:    1,
		KeyID:      keyID,
		DeviceCode: serial,
		Challenge:  challenge,
		Purpose:    Purpose,
		TicketID:   hex.EncodeToString(ticketID[:]),
		IssuedAt:   issuedAt.Unix(),
		ExpiresAt:  issuedAt.Add(lifetime).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", Claims{}, err
	}
	signed := append([]byte(signatureContext), payload...)
	signature := ed25519.Sign(privateKey, signed)
	token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	return token, claims, nil
}

// Verify checks a support-signed token against the local device and active
// challenge. The caller must atomically consume the challenge before resetting
// the password so the same ticket cannot be replayed.
func Verify(publicKeys map[string]ed25519.PublicKey, token, deviceCode, challenge string) (Claims, error) {
	return VerifyAt(publicKeys, token, deviceCode, challenge, time.Now().UTC())
}

// VerifyAt is the deterministic-clock form of Verify. The small clock-skew
// allowance is for an OEC whose NTP clock has drifted briefly; it does not
// make a ticket long-lived because the signed lifetime is capped at ten
// minutes and the allowance is fixed at two minutes.
func VerifyAt(publicKeys map[string]ed25519.PublicKey, token, deviceCode, challenge string, now time.Time) (Claims, error) {
	if len(token) > 2048 || !validChallenge(challenge) {
		return Claims{}, ErrInvalidTicket
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return Claims{}, ErrInvalidTicket
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(payload) == 0 || len(payload) > 1024 {
		return Claims{}, ErrInvalidTicket
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Claims{}, ErrInvalidTicket
	}
	var claims Claims
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&claims) != nil {
		return Claims{}, ErrInvalidTicket
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Claims{}, ErrInvalidTicket
	}
	canonical, err := json.Marshal(claims)
	if err != nil || string(canonical) != string(payload) {
		return Claims{}, ErrInvalidTicket
	}
	serial, _, err := identity.NormalizeMAC(deviceCode)
	if err != nil || claims.Version != 1 || claims.Purpose != Purpose || claims.DeviceCode != serial || claims.Challenge != challenge || !ValidKeyID(claims.KeyID) || len(claims.TicketID) != 32 {
		return Claims{}, ErrInvalidTicket
	}
	if _, err := hex.DecodeString(claims.TicketID); err != nil || claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt {
		return Claims{}, ErrInvalidTicket
	}
	issuedAt := time.Unix(claims.IssuedAt, 0)
	expiresAt := time.Unix(claims.ExpiresAt, 0)
	if expiresAt.Sub(issuedAt) <= 0 || expiresAt.Sub(issuedAt) > TicketLifetime {
		return Claims{}, ErrInvalidTicket
	}
	publicKey := publicKeys[claims.KeyID]
	if len(publicKey) != ed25519.PublicKeySize {
		return Claims{}, ErrInvalidTicket
	}
	if !ed25519.Verify(publicKey, append([]byte(signatureContext), payload...), signature) {
		return Claims{}, ErrInvalidTicket
	}
	now = now.UTC()
	if now.Before(issuedAt.Add(-TicketClockSkew)) || !now.Before(expiresAt.Add(TicketClockSkew)) {
		return Claims{}, ErrInvalidTicket
	}
	return claims, nil
}

// ParsePrivateKey accepts a hex, standard-base64, or raw-URL-base64 Ed25519
// private key. It never accepts a seed of ambiguous length.
func ParsePrivateKey(value string) (ed25519.PrivateKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrInvalidKey
	}
	var decoded []byte
	var err error
	if len(value) == ed25519.PrivateKeySize*2 {
		decoded, err = hex.DecodeString(value)
	} else {
		for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
			decoded, err = encoding.DecodeString(value)
			if err == nil {
				break
			}
		}
	}
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: expected %d encoded bytes", ErrInvalidKey, ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

// ParsePublicKey accepts the corresponding hex or base64 public key encoding.
func ParsePublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrInvalidKey
	}
	var decoded []byte
	var err error
	if len(value) == ed25519.PublicKeySize*2 {
		decoded, err = hex.DecodeString(value)
	} else {
		for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.StdEncoding, base64.RawURLEncoding, base64.URLEncoding} {
			decoded, err = encoding.DecodeString(value)
			if err == nil {
				break
			}
		}
	}
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: expected %d encoded bytes", ErrInvalidKey, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(decoded), nil
}

const (
	// ChallengeLifetime is the required local-manager challenge lifetime.
	ChallengeLifetime = 10 * time.Minute
	// TicketLifetime is signed into every administrator-issued authorization.
	TicketLifetime = 10 * time.Minute
	// TicketClockSkew is a bounded tolerance for a briefly unsynchronized OEC.
	TicketClockSkew = 2 * time.Minute
)
