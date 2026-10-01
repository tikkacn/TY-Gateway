// Package nodeprobe handles secret-free observations from dae's own HTTP checks.
package nodeprobe

import (
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DefaultURL = "http://cp.cloudflare.com"

type Settings struct {
	URL string `json:"url"`
}
type Result struct {
	ID        string     `json:"id"`
	Status    string     `json:"status"` // ok, failed, or unknown; unknown is never 0 ms.
	LatencyMS *int64     `json:"latency_ms,omitempty"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
}
type State struct {
	URL       string     `json:"url"`
	Results   []Result   `json:"results"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	Running   bool       `json:"running"`
}
type Request struct {
	Names []string `json:"names"`
}
type Observation struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	LatencyMS *int64    `json:"latency_ms,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// Only public HTTP(S) targets are accepted. No credentials, arbitrary ports,
// fragments, control characters or dae list separators may enter config.
func ValidateURL(raw string) error {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\t ,\\\"'{}") {
		return errors.New("invalid check URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("invalid check URL")
	}
	if port := u.Port(); port != "" && port != "80" && port != "443" {
		return errors.New("check port must be 80 or 443")
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if !PublicIPv4(addr) {
			return errors.New("check target must be public IPv4")
		}
	} else {
		if len(host) > 253 || !strings.Contains(host, ".") || strings.HasSuffix(strings.ToLower(host), ".local") {
			return errors.New("invalid public check hostname")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errors.New("invalid check hostname")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return errors.New("invalid check hostname")
				}
			}
		}
	}
	// url.Parse does not reject every malformed escaped host/path combination.
	if u.String() != raw {
		return errors.New("check URL must be canonical")
	}
	return nil
}

var excluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"),
}

func PublicIPv4(a netip.Addr) bool {
	if !a.Is4() || !a.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range excluded {
		if prefix.Contains(a) {
			return false
		}
	}
	return true
}

// Compile pins a resolved public IP so DNS rebinding cannot turn the health
// check into a request to the LAN. The original host still supplies HTTP Host/SNI.
func Compile(raw string, addr netip.Addr) (string, error) {
	if err := ValidateURL(raw); err != nil {
		return "", err
	}
	if !PublicIPv4(addr) {
		return "", errors.New("check IP must be public IPv4")
	}
	return raw + "," + addr.String(), nil
}
func ValidateCompiled(raw string) error {
	parts := strings.Split(raw, ",")
	if len(parts) != 2 {
		return errors.New("invalid compiled check target")
	}
	addr, err := netip.ParseAddr(parts[1])
	if err != nil {
		return errors.New("invalid check IP")
	}
	_, err = Compile(parts[0], addr)
	return err
}

var fields = regexp.MustCompile(`(?:^|\s)([a-z_0-9]+)=("(?:\\.|[^"\\])*"|[^\s]+)`)
var message = regexp.MustCompile(`(?:^|\]\s*|msg=")(Connectivity Check(?: Failed)?)(?:\s|"|$)`)

// ParseMessage only accepts native TCP/IPv4 check records; UDP, candidate group
// lists and traffic logs are not latency results. Never return raw errors/logs.
func ParseMessage(raw string, at time.Time) (Observation, bool) {
	if len(raw) > 16384 {
		return Observation{}, false
	}
	m := message.FindStringSubmatch(raw)
	if m == nil {
		return Observation{}, false
	}
	f := map[string]string{}
	for _, pair := range fields.FindAllStringSubmatch(raw, -1) {
		value := pair[2]
		if strings.HasPrefix(value, "\"") {
			var err error
			value, err = strconv.Unquote(value)
			if err != nil {
				return Observation{}, false
			}
		}
		f[pair[1]] = value
	}
	if f["network"] != "tcp4" || f["node"] == "" {
		return Observation{}, false
	}
	obs := Observation{Name: f["node"], Status: "failed", CheckedAt: at}
	if m[1] == "Connectivity Check" {
		d, err := time.ParseDuration(f["last"])
		if err != nil || d < 0 || d > 10*time.Minute {
			return Observation{}, false
		}
		ms := d.Milliseconds()
		obs.Status, obs.LatencyMS = "ok", &ms
	}
	return obs, true
}
