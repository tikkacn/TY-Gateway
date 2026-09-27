package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"tygateway/internal/model"
)

var softwareVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var softwareCommandIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

type softwareResult struct {
	State         string `json:"state"`
	TargetVersion string `json:"target_version,omitempty"`
	Error         string `json:"error,omitempty"`
}

// A cloud command can request only a signed channel/version or the device's
// own previous snapshot. The root updater accepts no URL, path, or shell text.
func (a *agent) remoteSoftwareCommand(ctx context.Context, command model.Command) (string, error) {
	if !softwareCommandIDPattern.MatchString(command.ID) {
		return "failed", nil
	}
	request := map[string]string{"command_id": command.ID}
	switch command.Command {
	case "software_update":
		parts := strings.Split(command.Payload, ":")
		if len(parts) != 2 || (parts[0] != "pilot" && parts[0] != "stable") || !validSoftwareVersion(parts[1]) {
			return "failed", nil
		}
		request["action"], request["channel"], request["version"] = "admin-apply", parts[0], parts[1]
	case "software_rollback":
		if !validSoftwareVersion(command.Payload) {
			return "failed", nil
		}
		request["action"], request["version"] = "admin-rollback", command.Payload
	default:
		return "failed", nil
	}
	status, err := a.softwareRequest(ctx, map[string]string{"action": "admin-status", "command_id": command.ID})
	if err != nil {
		return "", err
	}
	if status.State != "absent" {
		if command.Command == "software_update" && status.TargetVersion != "" && status.TargetVersion != request["version"] {
			return "failed", nil
		}
		return checkedSoftwareState(status.State)
	}
	started, err := a.softwareRequest(ctx, request)
	if err != nil {
		return "", err
	}
	return checkedSoftwareState(started.State)
}

func validSoftwareVersion(version string) bool {
	return len(version) <= 32 && softwareVersionPattern.MatchString(version)
}

func checkedSoftwareState(state string) (string, error) {
	switch state {
	case "running", "succeeded", "failed":
		return state, nil
	default:
		return "", errors.New("updater returned an unrecognized maintenance state")
	}
}

func (a *agent) softwareRequest(ctx context.Context, request map[string]string) (softwareResult, error) {
	if a.updateSocket == "" {
		return softwareResult{}, errors.New("administrator updater socket is unavailable")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", a.updateSocket)
	if err != nil {
		return softwareResult{}, errors.New("administrator updater is unavailable")
	}
	defer connection.Close()
	deadline := time.Now().Add(45 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	_ = connection.SetDeadline(deadline)
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return softwareResult{}, errors.New("administrator updater request failed")
	}
	var response softwareResult
	if err := json.NewDecoder(io.LimitReader(connection, 8192)).Decode(&response); err != nil {
		return softwareResult{}, errors.New("administrator updater response invalid")
	}
	if response.Error != "" {
		return softwareResult{}, fmt.Errorf("administrator updater declined command: %s", response.Error)
	}
	return response, nil
}
