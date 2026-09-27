package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"tygateway/internal/identity"
	"tygateway/internal/rules"
	"tygateway/internal/store"
)

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListDeviceEnrollments(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "device enrollments unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrollments": items})
}

func (s *Server) prepareEnrollment(w http.ResponseWriter, r *http.Request) {
	if s.isAdminSession(r) && !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var v struct {
		MAC            string `json:"mac"`
		Note           string `json:"note"`
		Profile        string `json:"profile"`
		SubscriptionID string `json:"subscription_id"`
	}
	if decodeJSON(r, &v) != nil {
		writeError(w, http.StatusBadRequest, "invalid enrollment request")
		return
	}
	if _, _, err := identity.NormalizeMAC(v.MAC); err != nil {
		writeError(w, http.StatusBadRequest, "invalid MAC address")
		return
	}
	profile := strings.TrimSpace(v.Profile)
	if profile == "" {
		profile = rules.ProfileGFW
	}
	if profile != rules.ProfileGFW && profile != rules.ProfileBlackmatrix && packageNames[profile] == "" {
		writeError(w, http.StatusBadRequest, "invalid rule profile")
		return
	}
	if packageNames[profile] != "" {
		if _, err := loadRulePackage(profile); err != nil {
			writeError(w, http.StatusConflict, "rule package unavailable")
			return
		}
	}
	record, err := s.Store.PrepareMACDeviceEnrollment(r.Context(), v.MAC, v.Note, profile, v.SubscriptionID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAlreadyRegistered), errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, "device or subscription already reserved")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "subscription not found")
		case errors.Is(err, store.ErrLimit):
			writeError(w, http.StatusBadRequest, "enrollment fields too long")
		default:
			writeError(w, http.StatusInternalServerError, "device enrollment could not be prepared")
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"enrollment": record})
}

func (s *Server) revokeEnrollment(w http.ResponseWriter, r *http.Request) {
	if s.isAdminSession(r) && !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var v struct {
		MAC string `json:"mac"`
	}
	if decodeJSON(r, &v) != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if _, _, err := identity.NormalizeMAC(v.MAC); err != nil {
		writeError(w, http.StatusBadRequest, "invalid MAC address")
		return
	}
	if err := s.Store.RevokeDeviceEnrollment(r.Context(), v.MAC); err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "only unused enrollments can be revoked")
		} else {
			writeError(w, http.StatusInternalServerError, "enrollment could not be revoked")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
