package subscription

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tygateway/internal/model"
)

var ErrInvalidKey = errors.New("subscription key must be 16, 24, or 32 bytes")
var ErrUnsafeURL = errors.New("subscription URL must be HTTPS and must not target a local address")

func KeyFromString(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrInvalidKey
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) >= 16 {
		return normalizeKey(b)
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) >= 16 {
		return normalizeKey(b)
	}
	// For deployment convenience a passphrase is deterministically expanded,
	// but the example production configuration still recommends a random 32-byte key.
	h := sha256.Sum256([]byte(raw))
	return h[:], nil
}

func normalizeKey(b []byte) ([]byte, error) {
	switch len(b) {
	case 16, 24, 32:
		return b, nil
	default:
		return nil, ErrInvalidKey
	}
}

func EncryptURL(plain string, key []byte) ([]byte, error) {
	key, err := normalizeKey(key)
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plain), nil), nil
}

func DecryptURL(ciphertext, key []byte) (string, error) {
	key, err := normalizeKey(key)
	if err != nil {
		return "", err
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(b)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}
	nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return "", errors.New("cannot decrypt subscription")
	}
	return string(plain), nil
}

func ValidateURL(raw string, allowHTTP bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 8192 || strings.ContainsAny(raw, "\r\n\x00") {
		return ErrUnsafeURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ErrUnsafeURL
	}
	if u.User != nil {
		return errors.New("subscription URL userinfo is not allowed")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return ErrUnsafeURL
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil && !publicIP(ip) {
		return ErrUnsafeURL
	}
	return nil
}

func FetchAndParse(ctx context.Context, rawURL string, allowHTTP bool) ([]model.Node, error) {
	body, err := FetchPayload(ctx, rawURL, allowHTTP, "TY-Gateway-Cloud/0.1", 2<<20)
	if err != nil {
		return nil, err
	}
	return ParsePayload(string(body))
}

// NameFilterStats describes the subscription-name policy applied before a
// provider payload reaches dae. The product convention is explicit: any node
// whose displayed name contains "IPv6" is excluded, case-insensitively.
type NameFilterStats struct {
	Input     int
	Kept      int
	IPv6Named int
	Invalid   int
}

// IsIPv6NamedNode reports whether the subscription's displayed node name is
// marked as IPv6. This is intentionally the only family-selection rule: node
// names are the operator-controlled source of truth for this deployment.
func IsIPv6NamedNode(name string) bool {
	return strings.Contains(strings.ToLower(name), "ipv6")
}

// FilterIPv6NamedNodes returns the nodes allowed by the name-based product
// policy. It is shared by the Cloud picker/policy path and the OEC payload
// filter so both sides expose the same set.
func FilterIPv6NamedNodes(nodes []model.Node) []model.Node {
	filtered := make([]model.Node, 0, len(nodes))
	for _, node := range nodes {
		if !IsIPv6NamedNode(node.Name) {
			filtered = append(filtered, node)
		}
	}
	return filtered
}

// ValidatedNodeMetadata maps dae's parsed display names back to the exact
// filtered subscription lines. It returns only customer-safe metadata: never
// an endpoint, credential, or raw subscription line. Ambiguous names fail
// closed because dae selects a named dialer by that same display name.
func ValidatedNodeMetadata(payload []byte, daeNames []string) ([]model.CustomerNode, error) {
	lines := subscriptionLines(decodePayloadText(string(payload)))
	byName := make(map[string]model.CustomerNode, len(lines))
	for _, line := range lines {
		name, ok := subscriptionLineName(line)
		if !ok || name == "" || len(name) > 255 || IsIPv6NamedNode(name) {
			return nil, errors.New("invalid filtered subscription node name")
		}
		if _, exists := byName[name]; exists {
			return nil, errors.New("ambiguous subscription node name")
		}
		byName[name] = model.CustomerNode{ID: stableID(line), Name: name}
	}
	if len(daeNames) == 0 || len(daeNames) > len(lines) {
		return nil, errors.New("invalid dae node inventory")
	}
	seen := make(map[string]bool, len(daeNames))
	seenID := make(map[string]bool, len(daeNames))
	validated := make([]model.CustomerNode, 0, len(daeNames))
	for _, name := range daeNames {
		node, ok := byName[name]
		if !ok || seen[name] || seenID[node.ID] {
			return nil, errors.New("dae node is absent or duplicated in subscription")
		}
		seen[name], seenID[node.ID] = true, true
		validated = append(validated, node)
	}
	return validated, nil
}

// FilterIPv6NamedPayload decodes a provider payload, removes only lines whose
// explicit display name contains "IPv6" (case-insensitively), and applies the
// narrow VMess allowInsecure numeric-boolean compatibility needed by dae. It
// does not resolve endpoints or reject dual-stack/IPv6 addresses; that
// behavior is deliberate per operator policy.
func FilterIPv6NamedPayload(payload []byte) ([]byte, NameFilterStats, error) {
	lines := subscriptionLines(decodePayloadText(string(payload)))
	stats := NameFilterStats{Input: len(lines)}
	if len(lines) == 0 {
		return nil, stats, errors.New("subscription has no node lines")
	}

	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		name, ok := subscriptionLineName(line)
		if !ok {
			stats.Invalid++
			continue
		}
		if IsIPv6NamedNode(name) {
			stats.IPv6Named++
			continue
		}
		stats.Kept++
		kept = append(kept, normalizeVMessAllowInsecure(line))
	}
	if len(kept) == 0 {
		return nil, stats, errors.New("subscription has no nodes without an IPv6 name marker")
	}
	return []byte(strings.Join(kept, "\n") + "\n"), stats, nil
}

// normalizeVMessAllowInsecure converts only the non-standard JSON numeric
// spellings 0 and 1 for VMess' boolean allowInsecure field. dae's VMess
// importer decodes that field into a bool; other values and fields remain
// untouched so malformed or ambiguous input is not silently made permissive.
func normalizeVMessAllowInsecure(line string) string {
	const scheme = "vmess://"
	if len(line) < len(scheme) || !strings.EqualFold(line[:len(scheme)], scheme) {
		return line
	}
	encoded := line[len(scheme):]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	padded := err == nil
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return line
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(decoded, &fields); err != nil {
		return line
	}
	raw, ok := fields["allowInsecure"]
	if !ok {
		return line
	}
	switch strings.TrimSpace(string(raw)) {
	case "0":
		fields["allowInsecure"] = json.RawMessage("false")
	case "1":
		fields["allowInsecure"] = json.RawMessage("true")
	default:
		return line
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return line
	}
	if padded {
		return line[:len(scheme)] + base64.StdEncoding.EncodeToString(normalized)
	}
	return line[:len(scheme)] + base64.RawStdEncoding.EncodeToString(normalized)
}

func subscriptionLineName(line string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(line), "vmess://") {
		name, ok := vmessName(line)
		return name, ok
	}
	u, err := url.Parse(line)
	if err != nil || u.Scheme == "" {
		return "", false
	}
	return u.Fragment, true
}

func vmessName(line string) (string, bool) {
	encoded := line[len("vmess://"):]
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return "", false
	}
	var metadata struct {
		Name string `json:"ps"`
	}
	if err := json.Unmarshal(decoded, &metadata); err != nil {
		return "", false
	}
	return metadata.Name, true
}

func decodePayloadText(payload string) string {
	text := strings.TrimSpace(payload)
	if strings.Contains(text, "://") {
		return text
	}
	for _, decode := range []func(string) ([]byte, error){base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString} {
		if decoded, err := decode(text); err == nil && strings.Contains(string(decoded), "://") {
			return string(decoded)
		}
	}
	return text
}

func subscriptionLines(payload string) []string {
	lines := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(payload, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// FetchPayload safely fetches provider data without interpreting it. The OEC
// config helper uses this to stage the provider response locally; dae itself
// remains the only parser of that payload.
func FetchPayload(ctx context.Context, rawURL string, allowHTTP bool, userAgent string, maxBytes int64) ([]byte, error) {
	if err := ValidateURL(rawURL, allowHTTP); err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > 10<<20 {
		return nil, errors.New("invalid subscription response limit")
	}
	transport := &http.Transport{DialContext: safeDial, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || ValidateURL(req.URL.String(), allowHTTP) != nil {
			return errors.New("unsafe subscription redirect")
		}
		return nil
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, errors.New("invalid subscription request")
	}
	if userAgent == "" {
		userAgent = "TY-Gateway-Cloud/0.1"
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		// Fetch errors must not include the URL: it commonly contains a reusable
		// provider token and may be returned to the device helper or admin UI.
		return nil, errors.New("subscription fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, errors.New("subscription response could not be read")
	}
	if int64(len(body)) > maxBytes {
		return nil, errors.New("subscription response too large")
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("empty subscription")
	}
	return body, nil
}

// Resolve once and dial the validated address directly, preventing DNS rebinding.
// No environment proxy is used; TLS still verifies the original hostname.
func safeDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrUnsafeURL
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, ErrUnsafeURL
	}
	for _, ip := range ips {
		if ip.Zone != "" || !publicIP(ip.IP) {
			return nil, ErrUnsafeURL
		}
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/32", "2002::/16", "64:ff9b::/96"} {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

func ParsePayload(payload string) ([]model.Node, error) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil, errors.New("empty subscription")
	}
	decoded := payload
	if !strings.Contains(decoded, "://") {
		if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload)); err == nil {
			decoded = string(b)
		} else if b, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(payload)); err == nil {
			decoded = string(b)
		}
	}
	var nodes []model.Node
	for _, line := range strings.Split(strings.ReplaceAll(decoded, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "vmess://") {
			if n, ok := parseVMess(line); ok {
				nodes = append(nodes, n)
			}
			continue
		}
		if n, ok := parseURI(line); ok {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return nil, errors.New("no supported proxy nodes found")
	}
	return nodes, nil
}

func parseVMess(raw string) (model.Node, bool) {
	b64 := strings.TrimPrefix(raw, "vmess://")
	b, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(b64)
	}
	if err != nil {
		return model.Node{}, false
	}
	var v struct {
		Psk  string `json:"psk"`
		Add  string `json:"add"`
		Port any    `json:"port"`
		ID   string `json:"id"`
		Aid  int    `json:"aid"`
		Net  string `json:"net"`
		Name string `json:"ps"`
	}
	if json.Unmarshal(b, &v) != nil || v.Add == "" {
		return model.Node{}, false
	}
	port := 0
	switch p := v.Port.(type) {
	case float64:
		port = int(p)
	case string:
		port, _ = strconv.Atoi(p)
	}
	if port < 1 || port > 65535 {
		return model.Node{}, false
	}
	return model.Node{ID: stableID(raw), Name: v.Name, Protocol: "vmess", Server: v.Add, Port: port, Params: map[string]string{"network": v.Net}}, true
}

func parseURI(raw string) (model.Node, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return model.Node{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "vless" && scheme != "trojan" && scheme != "ss" && scheme != "hysteria2" && scheme != "hy2" && scheme != "tuic" {
		return model.Node{}, false
	}
	port, _ := strconv.Atoi(u.Port())
	if u.Hostname() == "" || port < 1 || port > 65535 {
		return model.Node{}, false
	}
	name := u.Fragment
	name = strings.TrimPrefix(name, "#")
	if name == "" {
		name = scheme + "-" + u.Hostname()
	}
	params := map[string]string{}
	// Metadata only: arbitrary query parameters may contain passwords or tokens.
	return model.Node{ID: stableID(raw), Name: name, Protocol: scheme, Server: u.Hostname(), Port: port, Params: params}, true
}
func stableID(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:8]) }
