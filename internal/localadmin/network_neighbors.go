package localadmin

import (
	"bufio"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// NetworkNeighbor is a read-only snapshot of the IPv4 ARP cache. It is not a
// durable device inventory: a sleeping device may disappear until it talks on
// the LAN again, and a randomized MAC is reported exactly as observed.
type NetworkNeighbor struct {
	IP              string `json:"ip"`
	MAC             string `json:"mac"`
	Interface       string `json:"interface"`
	State           string `json:"state"`
	ReservationName string `json:"reservation_name,omitempty"`
	AlreadyReserved bool   `json:"already_reserved"`
}

func (s *Server) getNetworkNeighbors(w http.ResponseWriter, r *http.Request) {
	iface := s.interfaceName()
	neighbors, err := readARPNeighbors("/proc/net/arp", iface)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "当前无法读取局域网设备缓存"})
		return
	}
	s.networkMu.Lock()
	reservations := append([]NetworkReservation(nil), s.network.Reservations...)
	s.networkMu.Unlock()
	byMAC := make(map[string]NetworkReservation, len(reservations))
	for _, item := range reservations {
		byMAC[compactMAC(item.MAC)] = item
	}
	for i := range neighbors {
		if item, ok := byMAC[compactMAC(neighbors[i].MAC)]; ok {
			neighbors[i].AlreadyReserved = true
			neighbors[i].ReservationName = item.Name
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"neighbors": neighbors, "interface": iface, "observed_at": s.cfg.Now().UTC()})
}

func readARPNeighbors(path, interfaceName string) ([]NetworkNeighbor, error) {
	data, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer data.Close()

	result := make([]NetworkNeighbor, 0)
	scanner := bufio.NewScanner(data)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] == "IP" {
			continue
		}
		if interfaceName != "" && fields[5] != interfaceName {
			continue
		}
		ip := net.ParseIP(fields[0]).To4()
		if ip == nil {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 || isZeroMAC(mac) {
			continue
		}
		flags, _ := strconv.ParseUint(strings.TrimPrefix(fields[2], "0x"), 16, 32)
		state := "缓存"
		if flags&2 != 0 {
			state = "已发现"
		}
		result = append(result, NetworkNeighbor{IP: ip.String(), MAC: strings.ToUpper(mac.String()), Interface: fields[5], State: state})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].IP < result[j].IP })
	return result, nil
}

func compactMAC(raw string) string {
	mac, err := net.ParseMAC(strings.TrimSpace(raw))
	if err == nil && len(mac) == 6 {
		return hex.EncodeToString(mac)
	}
	return strings.ToLower(strings.NewReplacer(":", "", "-", "", ".", "").Replace(raw))
}
