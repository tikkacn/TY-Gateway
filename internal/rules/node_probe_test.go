package rules

import (
	"strings"
	"testing"
	"tygateway/internal/model"
)

func TestProbeTargetActuallyRendersInDAE(t *testing.T) {
	policy := model.DaePolicy{Profile: "gfw_precise", Interface: "eth0", ProxyEnabled: true, SubscriptionPresent: true, TCPCheckURL: "https://8.8.8.8/ping,8.8.8.8"}
	text, err := RenderDaeManaged(policy)
	if err != nil || !strings.Contains(text, `tcp_check_url: "https://8.8.8.8/ping,8.8.8.8"`) || !strings.Contains(text, "tcp_check_http_method: HEAD") {
		t.Fatalf("target not rendered: %v %s", err, text)
	}
	policy.TCPCheckURL = "http://127.0.0.1,127.0.0.1"
	if _, err := RenderDaeManaged(policy); err == nil {
		t.Fatal("unsafe target rendered")
	}
}
