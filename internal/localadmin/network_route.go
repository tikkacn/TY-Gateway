package localadmin

import (
	"tygateway/internal/hostnet"
)

func systemDefaultGateway() string {
	_, gateway := hostnet.DefaultRoute()
	return gateway
}

func parseDefaultGateway(data []byte) string {
	_, gateway := hostnet.ParseDefaultRoute(data)
	return gateway
}
