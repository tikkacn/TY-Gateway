package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"tygateway/internal/identity"
	"tygateway/internal/store"
	"tygateway/internal/subscription"
)

func lookupDigest(raw string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte("subscription-lookup-v1\x00" + strings.TrimSpace(raw)))
	return hex.EncodeToString(h.Sum(nil))
}
func (s *Server) updateIdentity(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		Email          string `json:"email"`
		SubscriptionID string `json:"subscription_id"`
	}
	if decodeJSON(r, &v) != nil || v.ID == "" || len([]rune(v.Name)) > 128 {
		writeError(w, 400, "invalid identity")
		return
	}
	email, err := identity.NormalizeEmail(v.Email)
	if err != nil {
		writeError(w, 400, "invalid email")
		return
	}
	d, err := s.Store.UpdateIdentity(r.Context(), v.ID, strings.TrimSpace(v.Name), email, v.SubscriptionID)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, 409, "email or subscription already bound")
		return
	}
	if err != nil {
		writeError(w, 400, "binding unavailable; check device and subscription")
		return
	}
	writeJSON(w, 200, map[string]any{"device": d})
}

// POST keeps sensitive search values out of URLs and normal access logs.
func (s *Server) lookupIdentity(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Kind  string `json:"kind"`
		Value string `json:"value"`
	}
	if decodeJSON(r, &v) != nil {
		writeError(w, 400, "invalid lookup")
		return
	}
	value := strings.TrimSpace(v.Value)
	subID := ""
	switch v.Kind {
	case "serial":
		serial, _, err := identity.NormalizeMAC(value)
		if err != nil {
			writeError(w, 400, "invalid device code")
			return
		}
		value = serial
	case "email":
		email, err := identity.NormalizeEmail(value)
		if err != nil || email == "" {
			writeError(w, 400, "invalid email")
			return
		}
		value = email
	case "subscription":
		target := lookupDigest(value, s.SubscriptionKey)
		sub, err := s.Store.FindSubscriptionByLookup(r.Context(), target)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 404, "binding not found")
			return
		}
		if err != nil {
			writeError(w, 503, "lookup unavailable")
			return
		}
		subID = sub.ID
	default:
		writeError(w, 400, "invalid lookup type")
		return
	}
	ds, err := s.Store.ListDevices(r.Context(), s.OfflineAfter)
	if err != nil {
		writeError(w, 503, "lookup unavailable")
		return
	}
	for _, d := range ds {
		if (v.Kind == "serial" && d.Serial == value) || (v.Kind == "email" && d.Email == value) || (v.Kind == "subscription" && d.SubscriptionID == subID) {
			writeJSON(w, 200, map[string]any{"device": d})
			return
		}
	}
	writeError(w, 404, "binding not found")
}

// revealSubscription is separate from list and lookup responses. It is only
// reachable after admin authentication and only runs after an explicit action
// in the admin console; device/customer APIs never call it.
func (s *Server) revealSubscription(w http.ResponseWriter, r *http.Request) {
	var v struct {
		ID string `json:"id"`
	}
	if decodeJSON(r, &v) != nil || strings.TrimSpace(v.ID) == "" {
		writeError(w, 400, "subscription id required")
		return
	}
	ciphertext, err := s.Store.GetSubscriptionCiphertext(r.Context(), strings.TrimSpace(v.ID))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "subscription not found")
		return
	}
	if err != nil {
		writeError(w, 503, "subscription unavailable")
		return
	}
	url, err := subscription.DecryptURL(ciphertext, s.SubscriptionKey)
	if err != nil {
		writeError(w, 503, "subscription unavailable")
		return
	}
	if s.Store.RecordEvent(r.Context(), v.ID, "subscription_reveal") != nil {
		writeError(w, 503, "audit unavailable")
		return
	}
	writeJSON(w, 200, map[string]string{"url": url})
}
