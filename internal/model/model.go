package model

import "time"

type DeviceState string

const (
	DevicePending  DeviceState = "pending"
	DeviceEnabled  DeviceState = "enabled"
	DeviceDisabled DeviceState = "disabled"
)

type Device struct {
	RulePackageVersion     string      `json:"rule_package_version,omitempty"`
	ID                     string      `json:"id"`
	DeviceNumber           int64       `json:"device_number"`
	Serial                 string      `json:"serial"`
	MAC                    string      `json:"mac"`
	Note                   string      `json:"note,omitempty"` // Administrator-only; never use as the customer name.
	Name                   string      `json:"name"`
	Email                  string      `json:"email,omitempty"`
	State                  DeviceState `json:"state"`
	Online                 bool        `json:"online"`
	LastSeen               *time.Time  `json:"last_seen,omitempty"`
	LastIP                 string      `json:"last_ip,omitempty"`
	FirmwareVersion        string      `json:"firmware_version"`
	AgentVersion           string      `json:"agent_version"`
	KernelVersion          string      `json:"kernel_version"`
	HardwareVersion        string      `json:"hardware_version"`
	Profile                string      `json:"profile"`
	ConfigVersion          int64       `json:"config_version"`
	SubscriptionID         string      `json:"subscription_id,omitempty"`
	RescueSSHPort          int         `json:"rescue_ssh_port,omitempty"` // Administrator-only FRPS mapping; omitted from CustomerDevice.
	CustomerOverrideAction string      `json:"customer_override_action,omitempty"`
	CustomerOverrideUntil  *time.Time  `json:"customer_override_until,omitempty"`
	CustomerSessionVersion int64       `json:"-"`
	CreatedAt              time.Time   `json:"created_at"`
	UpdatedAt              time.Time   `json:"updated_at"`
}

// CustomerDevice is an allowlist, deliberately excluding administrative data.
type CustomerDevice struct {
	ID                     string      `json:"id"`
	Serial                 string      `json:"serial"`
	Name                   string      `json:"name"`
	State                  DeviceState `json:"state"`
	Online                 bool        `json:"online"`
	Profile                string      `json:"profile"`
	ConfigVersion          int64       `json:"config_version"`
	CustomerOverrideAction string      `json:"customer_override_action,omitempty"`
	CustomerOverrideUntil  *time.Time  `json:"customer_override_until,omitempty"`
}

func (d Device) CustomerView() CustomerDevice {
	action, until := d.CustomerOverrideAction, d.CustomerOverrideUntil
	if action != "" && (until == nil || !until.After(time.Now().UTC())) {
		action, until = "", nil
	}
	return CustomerDevice{ID: d.ID, Serial: d.Serial, Name: d.Name, State: d.State, Online: d.Online, Profile: d.Profile, ConfigVersion: d.ConfigVersion, CustomerOverrideAction: action, CustomerOverrideUntil: until}
}

type DeviceAuth struct {
	ID         string
	Serial     string
	SecretHash string
	State      DeviceState
}

type CustomerAuth struct {
	ID                 string
	Serial             string
	CustomerAccessHash string
	State              DeviceState
	Version            int64
}

type CustomerNode struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Region string `json:"region,omitempty"`
	Group  string `json:"group,omitempty"`
}

type RegisterDeviceInput struct {
	MAC             string `json:"mac"`
	ActivationCode  string `json:"activation_code,omitempty"`
	DeviceSecret    string `json:"device_secret,omitempty"`
	FirmwareVersion string `json:"firmware_version"`
	AgentVersion    string `json:"agent_version"`
	KernelVersion   string `json:"kernel_version"`
	HardwareVersion string `json:"hardware_version"`
	IP              string `json:"ip,omitempty"`
}

// DeviceEnrollment is an administrator-prepared, one-time authorization.
// The activation code itself is returned only when the record is created.
type DeviceEnrollment struct {
	MAC            string     `json:"mac"`
	ClaimMode      string     `json:"claim_mode"`
	Note           string     `json:"note,omitempty"`
	Profile        string     `json:"profile,omitempty"`
	SubscriptionID string     `json:"subscription_id,omitempty"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ClaimedAt      *time.Time `json:"claimed_at,omitempty"`
	DeviceID       string     `json:"device_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

type DeviceReport struct {
	FirmwareVersion   string   `json:"firmware_version,omitempty"`
	AgentVersion      string   `json:"agent_version,omitempty"`
	KernelVersion     string   `json:"kernel_version,omitempty"`
	HardwareVersion   string   `json:"hardware_version,omitempty"`
	IP                string   `json:"ip,omitempty"`
	Status            string   `json:"status,omitempty"`
	CPUPercent        *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent     *float64 `json:"memory_percent,omitempty"`
	DaeSubscriptionID string   `json:"dae_subscription_id,omitempty"`
	DaeStatus         string   `json:"dae_status,omitempty"`
	DaeNodeCount      int      `json:"dae_node_count,omitempty"`
}

type Rule struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	SourceType string `json:"source_type"`
	Category   string `json:"category,omitempty"`
	MatchType  string `json:"match_type"`
	MatchValue string `json:"match_value"`
	Action     string `json:"action"`
	Priority   int    `json:"priority"`
	Enabled    bool   `json:"enabled"`
	DeviceID   string `json:"device_id,omitempty"`
	SourceIP   string `json:"source_ip,omitempty"`
	SourceMAC  string `json:"source_mac,omitempty"`
}

// CustomerSettingRule is the portable, customer-owned part of a rule. IDs and
// administrative metadata are deliberately excluded from configuration backups.
type CustomerSettingRule struct {
	MatchType  string `json:"match_type"`
	MatchValue string `json:"match_value"`
	Action     string `json:"action"`
}

type Node struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Protocol string            `json:"protocol"`
	Server   string            `json:"server"`
	Port     int               `json:"port"`
	Region   string            `json:"region,omitempty"`
	Group    string            `json:"group,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
}

type SubscriptionView struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Provider    string     `json:"provider"`
	Status      string     `json:"status"`
	NodeCount   int        `json:"node_count"`
	LastRefresh *time.Time `json:"last_refresh,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type Command struct {
	ID        string     `json:"id"`
	DeviceID  string     `json:"device_id"`
	Command   string     `json:"command"`
	Payload   string     `json:"payload,omitempty"`
	Status    string     `json:"status"`
	CreatedAt time.Time  `json:"created_at"`
	ClaimedAt *time.Time `json:"claimed_at,omitempty"`
	AckedAt   *time.Time `json:"acked_at,omitempty"`
}

type CompiledRule struct {
	RuleID        string `json:"rule_id"`
	Source        string `json:"source"`
	SourceType    string `json:"source_type,omitempty"`
	Category      string `json:"category,omitempty"`
	DefaultAction string `json:"default_action,omitempty"`
	Match         string `json:"match"`
	Action        string `json:"action"`
	Priority      int    `json:"priority"`
	Explanation   string `json:"explanation,omitempty"`
}

type DeviceConfig struct {
	RuleSeedVersion        string            `json:"rule_seed_version,omitempty"`
	RulePackageVersion     string            `json:"rule_package_version,omitempty"`
	Device                 CustomerDevice    `json:"device"`
	Profile                string            `json:"profile"`
	ConfigVersion          int64             `json:"config_version"`
	Rules                  []CompiledRule    `json:"rules"`
	Nodes                  []Node            `json:"nodes"`
	Rescue                 *RescueConfig     `json:"rescue,omitempty"`
	AutoFRP                *AutoFRPConfig    `json:"auto_frp,omitempty"`
	Preferences            map[string]string `json:"preferences"`
	BaseRules              []CompiledRule    `json:"base_rules"`
	ValidUntil             *time.Time        `json:"valid_until,omitempty"`
	ServerTime             time.Time         `json:"server_time"`
	DaeSubscriptionManaged bool              `json:"dae_subscription_managed,omitempty"`
	DaeSubscription        *DaeSubscription  `json:"dae_subscription,omitempty"`
}

// DaePolicy is a secret-free, validated routing description sent only from the
// local Agent to its privileged helper. Node credentials remain in dae's
// root-only subscription file.
type DaePolicy struct {
	RulePackageVersion  string         `json:"rule_package_version,omitempty"`
	Profile             string         `json:"profile"`
	ProxyEnabled        bool           `json:"proxy_enabled"`
	RecheckIPv4Only     bool           `json:"recheck_ipv4_only,omitempty"` // Legacy wire name: reapply the subscription node-name filter; never rendered into dae rules.
	Interface           string         `json:"interface,omitempty"`
	DNSBind             string         `json:"dns_bind,omitempty"`
	TCPCheckURL         string         `json:"tcp_check_url,omitempty"` // Local public URL plus pinned IPv4; not a cloud preference.
	SubscriptionPresent bool           `json:"subscription_present"`
	Rules               []CompiledRule `json:"rules"`
	Nodes               []Node         `json:"nodes"`
	DirectHosts         []string       `json:"direct_hosts"`
}

// DaeSubscription is delivered only by the HMAC-authenticated device config
// endpoint. It is deliberately absent from all customer-facing models.
type DaeSubscription struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type RescueConfig struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	RemotePort int    `json:"remote_port,omitempty"`
}

// AutoFRPConfig describes only the isolated per-device FRP listener. It is
// delivered through the device-authenticated config endpoint, never to the
// customer portal. FRP uses OIDC client credentials derived per device; the
// shared server token is never sent to or stored on a device.
type AutoFRPConfig struct {
	Host              string `json:"host"`
	ControlPort       int    `json:"control_port"`
	RemotePort        int    `json:"remote_port"`
	OIDCIssuer        string `json:"oidc_issuer"`
	OIDCAudience      string `json:"oidc_audience"`
	OIDCTokenEndpoint string `json:"oidc_token_endpoint"`
	TLSCA             string `json:"tls_ca_pem"`
}

type ExplainRequest struct {
	DeviceID     string `json:"device_id"`
	Domain       string `json:"domain,omitempty"`
	IP           string `json:"ip,omitempty"`
	SourceIP     string `json:"source_ip,omitempty"`
	SourceMAC    string `json:"source_mac,omitempty"`
	CountryCode  string `json:"country_code,omitempty"`
	IsLAN        bool   `json:"is_lan,omitempty"`
	IsManagement bool   `json:"is_management,omitempty"`
}

type ExplainResult struct {
	Profile    string         `json:"profile"`
	Matched    *CompiledRule  `json:"matched,omitempty"`
	Candidates []CompiledRule `json:"candidates"`
	Fallback   string         `json:"fallback"`
}
