package localadmin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadARPNeighborsFiltersInterfaceAndNormalizesMAC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "arp")
	data := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"10.23.42.20    0x1         0x2         aa:bb:cc:dd:ee:01     *        eth0\n" +
		"10.23.42.21    0x1         0x0         02-11-22-33-44-55     *        eth0\n" +
		"10.23.42.22    0x1         0x2         00:00:00:00:00:00     *        eth0\n" +
		"10.23.42.23    0x1         0x2         aa:bb:cc:dd:ee:03     *        wlan0\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	neighbors, err := readARPNeighbors(path, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if len(neighbors) != 2 {
		t.Fatalf("got %d neighbors, want 2: %#v", len(neighbors), neighbors)
	}
	if neighbors[0].IP != "10.23.42.20" || neighbors[0].MAC != "AA:BB:CC:DD:EE:01" || neighbors[0].State != "已发现" {
		t.Fatalf("unexpected first neighbor: %#v", neighbors[0])
	}
	if neighbors[1].MAC != "02:11:22:33:44:55" || neighbors[1].State != "缓存" {
		t.Fatalf("unexpected second neighbor: %#v", neighbors[1])
	}
}
