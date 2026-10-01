package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"tygateway/internal/model"
	"tygateway/internal/store"
)

// Support reset returns the customer's routing overlay to the current
// administrator baseline. It does not modify profile, subscription, device
// identity, FRP assignment, local password, or physical network settings.
func (s *Server) adminResetCustomerSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		DeviceID        string `json:"device_id"`
		ExpectedVersion int64  `json:"expected_version"`
		Confirm         string `json:"confirm"`
	}
	if decodeJSON(r, &input) != nil || strings.TrimSpace(input.DeviceID) == "" || input.ExpectedVersion < 1 || input.Confirm != "RESET_CUSTOMER_SETTINGS" {
		writeError(w, http.StatusBadRequest, "device, version and reset confirmation required")
		return
	}
	d, err := s.Store.GetDevice(r.Context(), input.DeviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if d.ConfigVersion != input.ExpectedVersion {
		writeError(w, http.StatusConflict, "configuration changed; refresh device details")
		return
	}
	if err := s.Store.RecordEvent(r.Context(), d.ID, "customer_settings_admin_reset_requested"); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit log unavailable")
		return
	}
	version, err := s.Store.ReplaceCustomerSettings(r.Context(), d.ID, input.ExpectedVersion, []model.CustomerSettingRule{}, map[string]string{})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "configuration changed; refresh device details")
		} else {
			writeError(w, http.StatusServiceUnavailable, "customer reset unavailable")
		}
		return
	}
	command, commandErr := s.Store.EnqueueCommand(r.Context(), model.Command{DeviceID: d.ID, Command: "reload_config", Payload: `{"reset_local_preferences":true}`})
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "config_version": version, "baseline_profile": d.Profile,
		"reload_queued": commandErr == nil && command.ID != "",
		"message":       "已清除客户自定义分流；基础规则未改变。设备在线后将重新同步。",
	})
}
