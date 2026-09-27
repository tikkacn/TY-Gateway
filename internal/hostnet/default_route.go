package hostnet

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// DefaultRoute returns the interface and IPv4 gateway from the lowest-metric
// usable default route in Linux's proc route table.
func DefaultRoute() (string, string) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", ""
	}
	return ParseDefaultRoute(data)
}

func ParseDefaultRoute(data []byte) (string, string) {
	bestMetric := ^uint64(0)
	var bestInterface, bestGateway string
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[0] == "" || fields[0] == "lo" || fields[1] != "00000000" {
			continue
		}
		gateway, errGateway := strconv.ParseUint(fields[2], 16, 32)
		flags, errFlags := strconv.ParseUint(fields[3], 16, 32)
		metric, errMetric := strconv.ParseUint(fields[6], 10, 32)
		if errGateway != nil || errFlags != nil || errMetric != nil || flags&3 != 3 || gateway == 0 {
			continue
		}
		if metric < bestMetric {
			bestMetric = metric
			bestInterface = fields[0]
			bestGateway = net.IPv4(byte(gateway), byte(gateway>>8), byte(gateway>>16), byte(gateway>>24)).String()
		}
	}
	return bestInterface, bestGateway
}
