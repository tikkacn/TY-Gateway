package subscription

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"tygateway/internal/model"
)

func TestEncryptDecryptDoesNotStorePlaintext(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plain := "https://sub.example.invalid/token-secret"
	ciphertext, err := EncryptURL(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(ciphertext) == plain {
		t.Fatal("ciphertext equals plaintext")
	}
	got, err := DecryptURL(ciphertext, key)
	if err != nil || got != plain {
		t.Fatalf("decrypt: %q %v", got, err)
	}
}

func TestParsePayload(t *testing.T) {
	nodes, err := ParsePayload("vless://uuid@example.com:443?security=tls#US-1\ntrojan://pw@example.net:443#HK-1")
	if err != nil || len(nodes) != 2 {
		t.Fatalf("nodes=%d err=%v", len(nodes), err)
	}
	if nodes[0].Server != "example.com" || nodes[1].Protocol != "trojan" {
		t.Fatalf("unexpected nodes: %#v", nodes)
	}
}

func TestFilterIPv6NamedPayloadUsesOnlyDisplayedNames(t *testing.T) {
	vmess, err := json.Marshal(map[string]any{"add": "v6.example", "port": 443, "id": "secret-id", "ps": "Backup-IPV6"})
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Join([]string{
		"vless://uuid@a.example:443#V4-HK",
		"trojan://pw@b.example:443#HK-IPv6",
		"vless://uuid@dual.example:443#sg-ipv6",
		"vless://uuid@[2001:db8::1]:443#manual-name-without-marker",
		"vmess://" + base64.StdEncoding.EncodeToString(vmess),
	}, "\n")

	filtered, stats, err := FilterIPv6NamedPayload([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	text := string(filtered)
	for _, want := range []string{"#V4-HK", "#manual-name-without-marker"} {
		if !strings.Contains(text, want) {
			t.Fatalf("filtered payload lost %s: %q", want, text)
		}
	}
	for _, unwanted := range []string{"#HK-IPv6", "#sg-ipv6", "Backup-IPV6"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("filtered payload retained %s: %q", unwanted, text)
		}
	}
	if stats.Input != 5 || stats.Kept != 2 || stats.IPv6Named != 3 || stats.Invalid != 0 {
		t.Fatalf("unexpected filter stats: %#v", stats)
	}
}

func TestFilterIPv6NamedPayloadDecodesBase64AndRejectsAllMarkedNodes(t *testing.T) {
	raw := "trojan://secret@node.example:443#jp-ipv6"
	payload := base64.StdEncoding.EncodeToString([]byte(raw))
	_, stats, err := FilterIPv6NamedPayload([]byte(payload))
	if err == nil || !strings.Contains(err.Error(), "no nodes without an IPv6 name marker") {
		t.Fatalf("expected all-marked rejection, got err=%v stats=%#v", err, stats)
	}
	if stats.Input != 1 || stats.IPv6Named != 1 {
		t.Fatalf("unexpected all-marked stats: %#v", stats)
	}
}

func TestFilterIPv6NamedPayloadNormalizesOnlyNumericVMessAllowInsecureBooleans(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "numeric false", value: 0, want: "false"},
		{name: "numeric true", value: 1, want: "true"},
		{name: "other number unchanged", value: 2, want: "2"},
		{name: "string unchanged", value: "0", want: `"0"`},
		{name: "boolean unchanged", value: true, want: "true"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vmess, err := json.Marshal(map[string]any{
				"add":           "node.example.invalid",
				"id":            "fixture-only",
				"ps":            "Fixture node",
				"allowInsecure": tc.value,
				"custom":        map[string]any{"preserved": "yes"},
			})
			if err != nil {
				t.Fatal(err)
			}
			line := "vmess://" + base64.StdEncoding.EncodeToString(vmess)
			filtered, stats, err := FilterIPv6NamedPayload([]byte(line))
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(filtered)), "vmess://"))
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(decoded, &got); err != nil {
				t.Fatal(err)
			}
			if value := string(got["allowInsecure"]); value != tc.want {
				t.Fatalf("allowInsecure=%s, want %s", value, tc.want)
			}
			if string(got["custom"]) != `{"preserved":"yes"}` {
				t.Fatalf("unrelated VMess fields changed: %s", got["custom"])
			}
			if stats.Input != 1 || stats.Kept != 1 || stats.Invalid != 0 {
				t.Fatalf("unexpected stats: %#v", stats)
			}
		})
	}
}

func TestFilterIPv6NamedPayloadVMessNormalizationIsIdempotent(t *testing.T) {
	vmess, err := json.Marshal(map[string]any{
		"add":           "node.example.invalid",
		"id":            "fixture-only",
		"ps":            "Fixture node",
		"allowInsecure": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, _, err := FilterIPv6NamedPayload([]byte("vmess://" + base64.StdEncoding.EncodeToString(vmess)))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := FilterIPv6NamedPayload(first)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("normalization changed an already-normalized subscription")
	}
}

func TestFilterIPv6NamedNodesMatchesPayloadPolicy(t *testing.T) {
	nodes := []model.Node{
		{ID: "v4", Name: "HK-JP"},
		{ID: "v6", Name: "GCC-HK-IPV6"},
		{ID: "mixed-case", Name: "Backup-iPv6"},
	}
	filtered := FilterIPv6NamedNodes(nodes)
	if len(filtered) != 1 || filtered[0].ID != "v4" {
		t.Fatalf("unexpected filtered nodes: %#v", filtered)
	}
}

func TestValidatedNodeMetadataUsesOnlyDaeAcceptedNames(t *testing.T) {
	payload := []byte("vless://secret@example.invalid:443#Japan\nvless://secret2@example.invalid:443#Singapore\n")
	nodes, err := ValidatedNodeMetadata(payload, []string{"Singapore"})
	if err != nil || len(nodes) != 1 || nodes[0].Name != "Singapore" || nodes[0].ID != stableID("vless://secret2@example.invalid:443#Singapore") {
		t.Fatalf("dae inventory mapping failed: %#v %v", nodes, err)
	}
	if _, err := ValidatedNodeMetadata(payload, []string{"unparsed"}); err == nil {
		t.Fatal("accepted a node dae did not parse from this subscription")
	}
	if _, err := ValidatedNodeMetadata([]byte("vless://x@example.invalid:443#HK-IPV6\n"), []string{"HK-IPV6"}); err == nil {
		t.Fatal("accepted an IPv6-labelled node")
	}
	if _, err := ValidatedNodeMetadata([]byte("vless://x@example.invalid:443#Duplicate\nvless://y@example.invalid:443#Duplicate\n"), []string{"Duplicate"}); err == nil {
		t.Fatal("accepted an ambiguous display name")
	}
}
