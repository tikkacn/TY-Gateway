package hostnet

import "testing"

func TestParseDefaultRouteSelectsLowestMetric(t *testing.T) {
	routes := []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"end0 00000000 012A170A 0003 0 0 100 00000000 0 0 0\n" +
		"enP2s0 00000000 012B170A 0003 0 0 50 00000000 0 0 0\n")
	iface, gateway := ParseDefaultRoute(routes)
	if iface != "enP2s0" || gateway != "10.23.43.1" {
		t.Fatalf("default route = (%q, %q), want (enP2s0, 10.23.43.1)", iface, gateway)
	}
}

func TestParseDefaultRouteIgnoresUnusableRows(t *testing.T) {
	routes := []byte("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" +
		"lo 00000000 0100007F 0003 0 0 1 00000000 0 0 0\n" +
		"end0 00000000 012A170A 0002 0 0 2 00000000 0 0 0\n" +
		"enP2s0 00000000 invalid 0003 0 0 3 00000000 0 0 0\n" +
		"eth0 00000000 00000000 0003 0 0 4 00000000 0 0 0\n")
	iface, gateway := ParseDefaultRoute(routes)
	if iface != "" || gateway != "" {
		t.Fatalf("unusable routes = (%q, %q), want empty", iface, gateway)
	}
}
