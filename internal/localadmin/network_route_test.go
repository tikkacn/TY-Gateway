package localadmin

import "testing"

func TestParseDefaultGatewaySelectsLowestMetricIPv4Route(t *testing.T) {
	routes := []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 012A170A 0003 0 0 100 00000000 0 0 0\n" +
		"eth1 00000000 012B170A 0003 0 0 50 00000000 0 0 0\n")
	if got := parseDefaultGateway(routes); got != "10.23.43.1" {
		t.Fatalf("default gateway = %q, want 10.23.43.1", got)
	}
}

func TestParseDefaultGatewayRejectsDownOrMalformedRoutes(t *testing.T) {
	routes := []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"eth0 00000000 0100A8C0 0002 0 0 10 00000000 0 0 0\n" +
		"eth1 00000000 not-hex 0003 0 0 1 00000000 0 0 0\n")
	if got := parseDefaultGateway(routes); got != "" {
		t.Fatalf("default gateway = %q, want empty", got)
	}
}
