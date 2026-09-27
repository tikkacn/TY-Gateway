package subscription

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestRejectNonPublicDestinations(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "224.0.0.1", "198.18.0.1", "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1"} {
		if publicIP(net.ParseIP(address)) {
			t.Fatalf("unsafe destination accepted: %s", address)
		}
	}
	if !publicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("public address rejected")
	}
	if conn, err := safeDial(context.Background(), "tcp", "localhost:80"); err == nil {
		conn.Close()
		t.Fatal("localhost connected")
	}
}

func TestNodeMetadataDoesNotExposeQueryCredentials(t *testing.T) {
	nodes, err := ParsePayload("vless://secret@example.com:443?password=hidden&token=hidden#test")
	if err != nil || len(nodes) != 1 {
		t.Fatal("parse failed")
	}
	for k, v := range nodes[0].Params {
		if strings.Contains(k+v, "hidden") {
			t.Fatal("credential exposed")
		}
	}
}
