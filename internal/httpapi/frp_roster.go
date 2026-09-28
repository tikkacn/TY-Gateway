package httpapi

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"tygateway/internal/frpauth"
	"tygateway/internal/model"
)

// frpRoster is a machine-only, read-only feed. It exports hashes of FRP-only
// derived credentials, never a Cloud device signing key or a raw FRP secret.
func (s *Server) frpRoster(w http.ResponseWriter, r *http.Request) {
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(s.FRPRosterToken) < 32 || len(provided) != len(s.FRPRosterToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(s.FRPRosterToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "FRP roster access denied")
		return
	}
	if s.FRPRosterPortStart < 1 || s.FRPRosterPortStart > s.FRPRosterPortEnd || s.FRPRosterPortEnd > 65535 {
		writeError(w, http.StatusServiceUnavailable, "FRP roster port range unavailable")
		return
	}
	ctx := r.Context()
	devices, err := s.Store.ListDevices(ctx, s.OfflineAfter)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "FRP roster unavailable")
		return
	}
	preparations, err := s.Store.ListDeviceEnrollments(ctx)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "FRP roster unavailable")
		return
	}
	approved := make(map[string]bool, len(preparations))
	for _, p := range preparations {
		if p.ClaimedAt != nil && p.DeviceID != "" && p.ClaimMode == "mac" {
			approved[p.DeviceID] = true
		}
	}
	roster := frpauth.Roster{GeneratedAt: time.Now().UTC(), Entries: make([]frpauth.Entry, 0, len(devices))}
	for _, d := range devices {
		if !approved[d.ID] || d.State != model.DeviceEnabled || d.RescueSSHPort < s.FRPRosterPortStart || d.RescueSSHPort > s.FRPRosterPortEnd {
			continue // Only MAC-claimed devices use the automatic per-device listener.
		}
		a, err := s.Store.GetDeviceAuth(ctx, d.ID)
		if err != nil || a.State != model.DeviceEnabled {
			writeError(w, http.StatusServiceUnavailable, "FRP roster unavailable")
			return
		}
		credential, err := frpauth.Credential(a.SecretHash, d.ID, d.RescueSSHPort)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "FRP roster unavailable")
			return
		}
		roster.Entries = append(roster.Entries, frpauth.Entry{DeviceID: d.ID, Port: d.RescueSSHPort, CredentialHash: frpauth.CredentialHash(credential)})
	}
	if err := roster.Validate(time.Now().UTC(), time.Minute, s.FRPRosterPortStart, s.FRPRosterPortEnd); err != nil {
		writeError(w, http.StatusServiceUnavailable, "FRP roster unavailable")
		return
	}
	writeJSON(w, http.StatusOK, roster)
}
