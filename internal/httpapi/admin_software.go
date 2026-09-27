package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"tygateway/internal/model"
	"tygateway/internal/store"
)

var adminReleaseVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// The remote maintenance protocol first ships with the 0.8.0 Agent. Older
// Agents acknowledge an unknown cloud command as failed, and cannot confirm
// a rollback after they replace the new Agent binary.
func remoteSoftwareSupported(agentVersion string) bool {
	if len(agentVersion) > 32 || !adminReleaseVersion.MatchString(agentVersion) {
		return false
	}
	parts := strings.Split(agentVersion, ".")
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil {
		return false
	}
	return major > 0 || minor >= 8
}

func (s *Server) adminSoftwareStatus(w http.ResponseWriter, r *http.Request) {
	deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
	if deviceID == "" {
		writeError(w, http.StatusBadRequest, "device_id required")
		return
	}
	device, err := s.Store.GetDevice(r.Context(), deviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	commands, err := s.Store.ListDeviceCommands(r.Context(), deviceID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "maintenance status unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"device_id": device.ID, "reported_agent_version": device.AgentVersion, "remote_supported": remoteSoftwareSupported(device.AgentVersion), "commands": commands})
}

// Admin software maintenance accepts no URL, path or executable. The device
// downloads only a pinned-key release of the explicitly approved version, or
// restores its own previous local snapshot. A queue acknowledgement is not an
// installation result; the Agent reports a final status after rechecking.
func (s *Server) adminSoftwareCommand(w http.ResponseWriter, r *http.Request) {
	if s.isAdminSession(r) && !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "same-origin request required")
		return
	}
	var input struct {
		DeviceID  string `json:"device_id"`
		Operation string `json:"operation"`
		Channel   string `json:"channel"`
		Version   string `json:"version"`
		Confirm   string `json:"confirm"`
	}
	body, err := readBody(r)
	if err != nil || len(body) == 0 || len(body) > 4096 {
		writeError(w, http.StatusBadRequest, "invalid software maintenance request")
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || input.DeviceID == "" || len(input.Version) > 32 || !adminReleaseVersion.MatchString(input.Version) {
		writeError(w, http.StatusBadRequest, "device and exact release version required")
		return
	}
	command := model.Command{DeviceID: input.DeviceID}
	switch input.Operation {
	case "update":
		if input.Channel != "stable" && input.Channel != "pilot" || input.Confirm != "UPDATE:"+input.Version {
			writeError(w, http.StatusBadRequest, "update channel and confirmation required")
			return
		}
		command.Command = "software_update"
		command.Payload = input.Channel + ":" + input.Version
	case "rollback":
		if input.Channel != "" || input.Confirm != "ROLLBACK:"+input.Version {
			writeError(w, http.StatusBadRequest, "rollback confirmation required")
			return
		}
		command.Command = "software_rollback"
		command.Payload = input.Version
	default:
		writeError(w, http.StatusBadRequest, "unsupported maintenance operation")
		return
	}
	device, err := s.Store.GetDevice(r.Context(), input.DeviceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	if device.State != model.DeviceEnabled {
		writeError(w, http.StatusConflict, "device must be enabled for software maintenance")
		return
	}
	if !remoteSoftwareSupported(device.AgentVersion) {
		writeError(w, http.StatusConflict, "device Agent does not support confirmed remote software maintenance")
		return
	}
	previous, err := s.Store.ListDeviceCommands(r.Context(), device.ID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "maintenance queue unavailable")
		return
	}
	for _, pending := range previous {
		if pending.Status == "queued" || pending.Status == "claimed" {
			writeError(w, http.StatusConflict, "a software maintenance command is already pending")
			return
		}
	}
	if err := s.Store.RecordEvent(r.Context(), device.ID, "admin_"+command.Command+"_requested"); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit log unavailable")
		return
	}
	queued, err := s.Store.EnqueueCommand(r.Context(), command)
	if err != nil {
		if err == store.ErrConflict {
			writeError(w, http.StatusConflict, "another software maintenance command is already pending")
		} else if err == store.ErrLimit {
			writeError(w, http.StatusConflict, "device command queue is full")
		} else {
			writeError(w, http.StatusServiceUnavailable, "maintenance command could not be queued")
		}
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"command": queued, "message": "已排队；只有设备确认签名安装或本地回退完成后才显示成功。"})
}
