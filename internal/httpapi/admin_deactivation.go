package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"tygateway/internal/identity"
	"tygateway/internal/store"
)

func (s *Server) adminDeactivateDevice(w http.ResponseWriter, r *http.Request) {
	if s.isAdminSession(r) && !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var input struct {
		DeviceID        string `json:"device_id"`
		ExpectedVersion int64  `json:"expected_version"`
		MAC             string `json:"mac"`
		Confirm         string `json:"confirm"`
	}
	if decodeJSON(r, &input) != nil || strings.TrimSpace(input.DeviceID) == "" || input.ExpectedVersion < 1 || input.Confirm != "DEACTIVATE_DEVICE" {
		writeError(w, http.StatusBadRequest, "device, version, MAC and deactivation confirmation required")
		return
	}
	if _, _, err := identity.NormalizeMAC(input.MAC); err != nil {
		writeError(w, http.StatusBadRequest, "invalid confirmation MAC")
		return
	}
	enrollment, err := s.Store.DeactivateDevice(r.Context(), input.DeviceID, input.ExpectedVersion, input.MAC)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "device no longer exists; refresh device list")
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "device or assignment changed; refresh details and confirm MAC")
		default:
			writeError(w, http.StatusServiceUnavailable, "deactivation not confirmed; refresh device list before retry")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "enrollment": enrollment, "frp_revocation": "pending_roster_refresh",
		"message": "旧身份已撤销，MAC 已恢复待激活。FRP 授权随服务端名单同步撤销；重新刷机安装后可生成新身份认领。",
	})
}
