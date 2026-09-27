package identity

import (
	"errors"
	"net/mail"
	"strings"
)

// Product policy: email lookup is case-insensitive; do not strip plus tags or dots.
func NormalizeEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", nil
	}
	if len(value) > 254 {
		return "", errors.New("invalid email")
	}
	for _, c := range value {
		if c > 127 {
			return "", errors.New("invalid email")
		}
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return "", errors.New("invalid email")
	}
	return value, nil
}
