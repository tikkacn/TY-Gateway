package localadmin

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// NetworkPlanInput describes LAN settings. Preview only validates; actual
// application uses the separate authenticated helper APIs.
type NetworkPlanInput struct {
	AddressCIDR string   `json:"address_cidr"`
	Gateway     string   `json:"gateway"`
	DHCPEnabled bool     `json:"dhcp_enabled"`
	PoolStart   string   `json:"pool_start"`
	PoolEnd     string   `json:"pool_end"`
	DNSMode     string   `json:"dns_mode"`
	DNSServers  []string `json:"dns_servers"`
}

type NetworkPlanPreview struct {
	Valid          bool     `json:"valid"`
	ApplyEnabled   bool     `json:"apply_enabled"`
	AddressCIDR    string   `json:"address_cidr,omitempty"`
	Gateway        string   `json:"gateway,omitempty"`
	ClientGateway  string   `json:"client_gateway,omitempty"`
	DHCPEnabled    bool     `json:"dhcp_enabled"`
	PoolStart      string   `json:"pool_start,omitempty"`
	PoolEnd        string   `json:"pool_end,omitempty"`
	DNSMode        string   `json:"dns_mode,omitempty"`
	DNSServers     []string `json:"dns_servers,omitempty"`
	DNSDescription string   `json:"dns_description,omitempty"`
	Warnings       []string `json:"warnings"`
}

var errInvalidNetworkPlan = errors.New("网络方案参数无效，请检查地址、网关、DHCP 地址池和 DNS 设置。")

// PreviewNetworkPlan validates a proposed one-interface LAN gateway plan.
// It intentionally cannot apply or save the plan; privileged application
// requires a separate, rollback-capable implementation.
func PreviewNetworkPlan(input NetworkPlanInput) (NetworkPlanPreview, error) {
	address, err := netip.ParsePrefix(strings.TrimSpace(input.AddressCIDR))
	if err != nil || !address.Addr().Is4() || address.Bits() < 8 || address.Bits() > 30 {
		return NetworkPlanPreview{}, errInvalidNetworkPlan
	}
	address = netip.PrefixFrom(address.Addr(), address.Bits())
	network := address.Masked()
	if !usableIPv4Host(address.Addr(), network) {
		return NetworkPlanPreview{}, errInvalidNetworkPlan
	}

	gateway, err := parseUsableIPv4(strings.TrimSpace(input.Gateway))
	if err != nil || !network.Contains(gateway) || !usableIPv4Host(gateway, network) || gateway == address.Addr() {
		return NetworkPlanPreview{}, errInvalidNetworkPlan
	}

	preview := NetworkPlanPreview{
		Valid:        true,
		ApplyEnabled: false,
		AddressCIDR:  address.String(),
		Gateway:      gateway.String(),
		DHCPEnabled:  input.DHCPEnabled,
		DNSMode:      input.DNSMode,
		Warnings: []string{
			"这只是方案校验，不会更改网络、DHCP、DNS 或防火墙。",
			"应用前必须确认主路由 DHCP 已关闭，并在路由器中核对管理地址及地址池没有冲突。",
		},
	}

	if input.DHCPEnabled {
		preview.ClientGateway = address.Addr().String()
		start, startErr := parseUsableIPv4(strings.TrimSpace(input.PoolStart))
		end, endErr := parseUsableIPv4(strings.TrimSpace(input.PoolEnd))
		if startErr != nil || endErr != nil || !network.Contains(start) || !network.Contains(end) ||
			!usableIPv4Host(start, network) || !usableIPv4Host(end, network) ||
			start == address.Addr() || end == address.Addr() || start == gateway || end == gateway ||
			ipv4Number(start) > ipv4Number(end) || ipv4Number(end)-ipv4Number(start) > 4095 {
			return NetworkPlanPreview{}, errInvalidNetworkPlan
		}
		if ipv4Number(address.Addr()) >= ipv4Number(start) && ipv4Number(address.Addr()) <= ipv4Number(end) {
			return NetworkPlanPreview{}, errInvalidNetworkPlan
		}
		if ipv4Number(gateway) >= ipv4Number(start) && ipv4Number(gateway) <= ipv4Number(end) {
			return NetworkPlanPreview{}, errInvalidNetworkPlan
		}
		preview.PoolStart, preview.PoolEnd = start.String(), end.String()
		preview.Warnings = append(preview.Warnings,
			"DHCP 地址池只避开了 OEC 和网关地址；本机无法得知路由器里的静态设备或离线设备，请先核对并迁移原有 MAC/IP 绑定。")
	}

	switch input.DNSMode {
	case "router":
		if len(input.DNSServers) != 0 {
			return NetworkPlanPreview{}, errInvalidNetworkPlan
		}
		preview.DNSDescription = "使用主路由地址作为上游 DNS；主路由必须继续提供 DNS 转发。"
		preview.Warnings = append(preview.Warnings,
			"这里的“自动 DNS”不是自动获知运营商 DNS；主路由关闭 DHCP 后，OEC 不会再从它获得 DHCP 下发的 DNS 地址。")
	case "custom":
		if len(input.DNSServers) == 0 || len(input.DNSServers) > 2 {
			return NetworkPlanPreview{}, errInvalidNetworkPlan
		}
		seen := make(map[netip.Addr]struct{}, len(input.DNSServers))
		for _, raw := range input.DNSServers {
			server, parseErr := parseUsableIPv4(strings.TrimSpace(raw))
			if parseErr != nil {
				return NetworkPlanPreview{}, errInvalidNetworkPlan
			}
			if _, exists := seen[server]; exists {
				return NetworkPlanPreview{}, errInvalidNetworkPlan
			}
			seen[server] = struct{}{}
			preview.DNSServers = append(preview.DNSServers, server.String())
		}
		preview.DNSDescription = fmt.Sprintf("使用指定 DNS：%s。", strings.Join(preview.DNSServers, "、"))
		preview.Warnings = append(preview.Warnings, "请确认指定 DNS 地址可从 OEC 网络访问。")
	default:
		return NetworkPlanPreview{}, errInvalidNetworkPlan
	}

	return preview, nil
}

func parseUsableIPv4(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(raw)
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
		return netip.Addr{}, errInvalidNetworkPlan
	}
	return address, nil
}

func usableIPv4Host(address netip.Addr, network netip.Prefix) bool {
	if !network.Contains(address) {
		return false
	}
	networkNumber := ipv4Number(network.Masked().Addr())
	broadcastNumber := networkNumber | (uint32(1)<<(32-network.Bits()) - 1)
	number := ipv4Number(address)
	return number > networkNumber && number < broadcastNumber
}

func ipv4Number(address netip.Addr) uint32 {
	bytes := address.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
