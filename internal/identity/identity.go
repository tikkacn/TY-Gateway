package identity

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var ErrInvalidMAC = errors.New("invalid MAC address")
var macPattern = regexp.MustCompile(`^[0-9A-F]{12}$`)

func NormalizeMAC(raw string) (string, string, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	s = strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(s)
	if !macPattern.MatchString(s) {
		return "", "", ErrInvalidMAC
	}
	return s, s, nil
}

func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("secure random unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}

func NewSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("secure random unavailable: %v", err))
	}
	return hex.EncodeToString(b)
}
