package httpapi

import (
	"net/http"
	"strings"
	"time"

	"tygateway/internal/identity"
	"tygateway/internal/recovery"
)

// issueRecoveryAuthorization signs a narrowly scoped, one-time authorization.
// The local OEC validates it offline; neither the device's MAC nor its serial
// is treated as a credential.
func (s *Server) issueRecoveryAuthorization(w http.ResponseWriter, r *http.Request) {
	if len(s.RecoverySigningKey) == 0 || s.RecoveryKeyID == "" {
		writeError(w, http.StatusServiceUnavailable, "local recovery signing is not configured")
		return
	}
	var input struct {
		DeviceCode string `json:"device_code"`
		Challenge  string `json:"challenge"`
	}
	if decodeJSON(r, &input) != nil {
		writeError(w, http.StatusBadRequest, "invalid recovery request")
		return
	}
	serial, _, err := identity.NormalizeMAC(input.DeviceCode)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid device code")
		return
	}
	if !s.recoveryLimits.allow("device:"+serial, 5) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "recovery issuance rate exceeded")
		return
	}
	authRecord, err := s.Store.GetCustomerAuthBySerial(r.Context(), serial)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	token, claims, err := recovery.SignAt(s.RecoverySigningKey, s.RecoveryKeyID, serial, strings.TrimSpace(input.Challenge), time.Now().UTC(), recovery.TicketLifetime)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid recovery challenge")
		return
	}
	// Audit before releasing the one-time token. Never record the challenge or
	// authorization token itself.
	if err := s.Store.RecordEvent(r.Context(), authRecord.ID, "recovery_ticket_issue"); err != nil {
		writeError(w, http.StatusServiceUnavailable, "recovery audit unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":   serial,
		"purpose":       recovery.Purpose,
		"authorization": token,
		"issued_at":     time.Unix(claims.IssuedAt, 0).UTC(),
		"expires_at":    time.Unix(claims.ExpiresAt, 0).UTC(),
		"instructions":  "输入设备本地恢复页面；授权默认 10 分钟有效，并且只匹配本设备当前挑战码，设备成功使用后立即失效。",
	})
}
