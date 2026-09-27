package localadmin

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const networkSettingsFile = "network-settings.json"

// NetworkSettings contains saved LAN configuration. Applying it requires the
// separate authenticated network/services operation and privileged helper.
type NetworkSettings struct {
	Plan         NetworkPlanInput     `json:"plan"`
	DNSEnabled   bool                 `json:"dns_enabled"`
	Reservations []NetworkReservation `json:"reservations"`
	UpdatedAt    *time.Time           `json:"updated_at,omitempty"`
}

type NetworkReservation struct {
	Name string `json:"name"`
	MAC  string `json:"mac"`
	IP   string `json:"ip"`
}

type NetworkSettingsResponse struct {
	Settings       NetworkSettings `json:"settings"`
	Applied        bool            `json:"applied"`
	DHCPActive     bool            `json:"dhcp_active"`
	DNSActive      bool            `json:"lan_dns_active"`
	ApplyAvailable bool            `json:"apply_available"`
	Notice         string          `json:"notice"`
	RuntimeKnown   bool            `json:"runtime_known"`
	ServiceState   string          `json:"service_state,omitempty"`
}

func (s *Server) networkSettingsResponse(settings NetworkSettings) NetworkSettingsResponse {
	response := NetworkSettingsResponse{Settings: settings, ApplyAvailable: s.cfg.NetworkSocket != "", Notice: "设置已保存；点击保存并应用配置后，DHCP/DNS 与地址绑定才会实际生效。"}
	if s.cfg.NetworkSocket == "" {
		return response
	}
	status, err := s.networkCall(map[string]string{"action": "lan_status"})
	if err != nil {
		response.Notice = "设置已保存，但当前无法读取服务运行状态。"
		return response
	}
	response.RuntimeKnown = true
	response.ServiceState = status.ServiceState
	response.DHCPActive = status.DHCPActive
	response.DNSActive = status.DNSActive
	want, _ := json.Marshal(settings)
	actual, _ := json.Marshal(status.AppliedSettings)
	response.Applied = string(want) == string(actual) && settings.Plan.DHCPEnabled == status.DHCPActive && settings.DNSEnabled == status.DNSActive
	return response
}

var errInvalidNetworkSettings = errors.New("网络配置预设无效；请检查地址池、DNS 和 IP/MAC 绑定")

func validateNetworkSettings(settings NetworkSettings) (NetworkSettings, error) {
	if len(settings.Reservations) > 256 {
		return NetworkSettings{}, errInvalidNetworkSettings
	}
	if settings.Plan.DHCPEnabled && !settings.DNSEnabled {
		return NetworkSettings{}, errInvalidNetworkSettings
	}
	preview, err := PreviewNetworkPlan(settings.Plan)
	if err != nil {
		return NetworkSettings{}, errInvalidNetworkSettings
	}
	address, _ := netip.ParsePrefix(preview.AddressCIDR)
	address = netip.PrefixFrom(address.Addr(), address.Bits())
	network := address.Masked()
	gateway, _ := netip.ParseAddr(preview.Gateway)
	poolStart, poolEnd := uint32(0), uint32(0)
	if preview.DHCPEnabled {
		start, _ := netip.ParseAddr(preview.PoolStart)
		end, _ := netip.ParseAddr(preview.PoolEnd)
		poolStart, poolEnd = ipv4Number(start), ipv4Number(end)
	}

	seenMAC := make(map[string]struct{}, len(settings.Reservations))
	seenIP := make(map[netip.Addr]struct{}, len(settings.Reservations))
	clean := make([]NetworkReservation, 0, len(settings.Reservations))
	for _, item := range settings.Reservations {
		name := strings.TrimSpace(item.Name)
		if len(name) > 64 || strings.ContainsAny(name, "\r\n\x00") {
			return NetworkSettings{}, errInvalidNetworkSettings
		}
		macText := strings.ToUpper(strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(item.MAC)))
		macBytes, err := hex.DecodeString(macText)
		mac := net.HardwareAddr(macBytes)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || isZeroMAC(mac) {
			return NetworkSettings{}, errInvalidNetworkSettings
		}
		normalizedMAC := strings.ToUpper(strings.ReplaceAll(mac.String(), ":", ""))
		ip, err := parseUsableIPv4(strings.TrimSpace(item.IP))
		if err != nil || !network.Contains(ip) || ip == address.Addr() || ip == gateway {
			return NetworkSettings{}, errInvalidNetworkSettings
		}
		number := ipv4Number(ip)
		if settings.Plan.DHCPEnabled && number >= poolStart && number <= poolEnd {
			return NetworkSettings{}, errInvalidNetworkSettings
		}
		if _, ok := seenMAC[normalizedMAC]; ok {
			return NetworkSettings{}, errInvalidNetworkSettings
		}
		if _, ok := seenIP[ip]; ok {
			return NetworkSettings{}, errInvalidNetworkSettings
		}
		seenMAC[normalizedMAC], seenIP[ip] = struct{}{}, struct{}{}
		clean = append(clean, NetworkReservation{Name: name, MAC: normalizedMAC, IP: ip.String()})
	}
	settings.Plan.AddressCIDR = preview.AddressCIDR
	settings.Plan.Gateway = preview.Gateway
	settings.Plan.PoolStart = preview.PoolStart
	settings.Plan.PoolEnd = preview.PoolEnd
	settings.Plan.DNSServers = append([]string(nil), preview.DNSServers...)
	settings.Reservations = clean
	return settings, nil
}

func isZeroMAC(mac net.HardwareAddr) bool {
	for _, value := range mac {
		if value != 0 {
			return false
		}
	}
	return true
}

func loadNetworkSettings(stateDir string) (NetworkSettings, error) {
	path := filepath.Join(stateDir, networkSettingsFile)
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return NetworkSettings{Reservations: []NetworkReservation{}}, nil
	}
	if err != nil {
		return NetworkSettings{}, fmt.Errorf("inspect network settings: %w", err)
	}
	if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return NetworkSettings{}, errors.New("network settings file permissions are too broad")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return NetworkSettings{}, fmt.Errorf("read network settings: %w", err)
	}
	var settings NetworkSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		return NetworkSettings{}, errors.New("network settings file is invalid")
	}
	validated, err := validateNetworkSettings(settings)
	if err != nil {
		return NetworkSettings{}, errors.New("network settings file failed validation")
	}
	validated.UpdatedAt = settings.UpdatedAt
	return validated, nil
}

func saveNetworkSettings(stateDir string, settings NetworkSettings) error {
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".network-settings-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(stateDir, networkSettingsFile)); err != nil {
		return err
	}
	if dir, err := os.Open(stateDir); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}
