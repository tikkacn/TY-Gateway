package localadmin

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func validNetworkSettings() NetworkSettings {
	return NetworkSettings{
		Plan: NetworkPlanInput{
			AddressCIDR: "10.23.42.211/24",
			Gateway:     "10.23.42.1",
			DHCPEnabled: true,
			PoolStart:   "10.23.42.100",
			PoolEnd:     "10.23.42.200",
			DNSMode:     "custom",
			DNSServers:  []string{"1.1.1.1"},
		},
		DNSEnabled: true,
		Reservations: []NetworkReservation{
			{Name: "Living room TV", MAC: "02:11:22:33:44:55", IP: "10.23.42.20"},
		},
	}
}

func TestValidateNetworkSettingsNormalizesReservations(t *testing.T) {
	got, err := validateNetworkSettings(validNetworkSettings())
	if err != nil {
		t.Fatal(err)
	}
	if got.Reservations[0].MAC != "021122334455" || got.Reservations[0].IP != "10.23.42.20" {
		t.Fatalf("reservation was not normalized: %#v", got.Reservations[0])
	}
}

func TestValidateNetworkSettingsRejectsDuplicateAndUnsafeReservations(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NetworkSettings)
	}{
		{name: "duplicate mac", change: func(v *NetworkSettings) {
			v.Reservations = append(v.Reservations, NetworkReservation{MAC: "02:11:22:33:44:55", IP: "10.23.42.21"})
		}},
		{name: "duplicate ip", change: func(v *NetworkSettings) {
			v.Reservations = append(v.Reservations, NetworkReservation{MAC: "02:11:22:33:44:56", IP: "10.23.42.20"})
		}},
		{name: "multicast mac", change: func(v *NetworkSettings) { v.Reservations[0].MAC = "01:11:22:33:44:55" }},
		{name: "address inside dynamic pool", change: func(v *NetworkSettings) { v.Reservations[0].IP = "10.23.42.110" }},
		{name: "outside subnet", change: func(v *NetworkSettings) { v.Reservations[0].IP = "10.23.43.20" }},
		{name: "gateway address", change: func(v *NetworkSettings) { v.Reservations[0].IP = "10.23.42.1" }},
		{name: "name injection", change: func(v *NetworkSettings) { v.Reservations[0].Name = "TV\nmalicious" }},
		{name: "dhcp without local dns", change: func(v *NetworkSettings) { v.DNSEnabled = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := validNetworkSettings()
			tc.change(&input)
			if _, err := validateNetworkSettings(input); err == nil {
				t.Fatal("unsafe or duplicate reservation accepted")
			}
		})
	}
}

func TestNetworkSettingsPersistPrivateAndRejectLooseFile(t *testing.T) {
	dir := t.TempDir()
	settings, err := validateNetworkSettings(validNetworkSettings())
	if err != nil {
		t.Fatal(err)
	}
	if err := saveNetworkSettings(dir, settings); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, networkSettingsFile))
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("network settings not private: info=%v err=%v", info, err)
	}
	loaded, err := loadNetworkSettings(dir)
	if err != nil || len(loaded.Reservations) != 1 {
		data, _ := os.ReadFile(filepath.Join(dir, networkSettingsFile))
		t.Fatalf("network settings failed to reload: %#v err=%v data=%s", loaded, err, data)
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.Chmod(filepath.Join(dir, networkSettingsFile), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadNetworkSettings(dir); err == nil {
		t.Fatal("settings with overly broad permissions were accepted")
	}
}
