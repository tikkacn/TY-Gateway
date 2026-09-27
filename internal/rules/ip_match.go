package rules

import (
	"errors"
	"net/netip"
	"strings"
)

// NormalizeIPMatchValue validates and canonicalizes a comma-separated list of
// literal IP addresses and CIDR prefixes for routing rules.
func NormalizeIPMatchValue(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" || len(raw) > 1024 {
		return "", errors.New("invalid IP/CIDR match value")
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return "", errors.New("invalid IP/CIDR match value")
		}
		if prefix, err := netip.ParsePrefix(part); err == nil {
			values = append(values, prefix.Masked().String())
			continue
		}
		address, err := netip.ParseAddr(part)
		if err != nil || address.Zone() != "" {
			return "", errors.New("invalid IP/CIDR match value")
		}
		values = append(values, address.Unmap().String())
	}
	return strings.Join(values, ","), nil
}
