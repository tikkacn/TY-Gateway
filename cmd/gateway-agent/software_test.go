package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"tygateway/internal/model"
)

func TestRemoteSoftwareCommandWaitsForVerifiedCompletion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updater.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	var mu sync.Mutex
	started := false
	completed := false
	requests := []string{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var request map[string]string
			_ = json.NewDecoder(conn).Decode(&request)
			mu.Lock()
			requests = append(requests, request["action"])
			response := map[string]string{"state": "absent"}
			if request["action"] == "admin-apply" {
				started = true
				response["state"] = "running"
			} else if started {
				response["state"] = "running"
				if completed {
					response["state"] = "succeeded"
				}
			}
			mu.Unlock()
			_ = json.NewEncoder(conn).Encode(response)
			_ = conn.Close()
		}
	}()
	a := &agent{updateSocket: path}
	command := model.Command{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Command: "software_update", Payload: "pilot:0.8.0"}
	state, err := a.remoteSoftwareCommand(context.Background(), command)
	if err != nil || state != "running" {
		t.Fatalf("first attempt=%q %v", state, err)
	}
	state, err = a.remoteSoftwareCommand(context.Background(), command)
	if err != nil || state != "running" {
		t.Fatalf("in-progress attempt=%q %v", state, err)
	}
	mu.Lock()
	completed = true
	mu.Unlock()
	state, err = a.remoteSoftwareCommand(context.Background(), command)
	if err != nil || state != "succeeded" {
		t.Fatalf("completed attempt=%q %v", state, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 4 || requests[0] != "admin-status" || requests[1] != "admin-apply" || requests[2] != "admin-status" || requests[3] != "admin-status" {
		t.Fatalf("maintenance command launched more than once: %#v", requests)
	}
}

func TestRemoteSoftwareCommandRejectsUnexpectedPayload(t *testing.T) {
	if validSoftwareVersion("0.8.0; rm") || validSoftwareVersion("00.8.0") || !validSoftwareVersion("0.8.0") {
		t.Fatal("software version validator is unsafe")
	}
}

func TestPollCommandsAcknowledgesOnlyAfterUpdaterConfirms(t *testing.T) {
	path := filepath.Join(t.TempDir(), "updater.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable: %v", err)
	}
	defer listener.Close()
	var mu sync.Mutex
	completed := false
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var request map[string]string
			_ = json.NewDecoder(conn).Decode(&request)
			mu.Lock()
			state := "running"
			if completed {
				state = "succeeded"
			}
			mu.Unlock()
			_ = json.NewEncoder(conn).Encode(map[string]string{"state": state})
			_ = conn.Close()
		}
	}()
	acknowledgements := []string{}
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/commands") {
			_ = json.NewEncoder(w).Encode(commandEnvelope{Commands: []model.Command{{ID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Command: "software_update", Payload: "pilot:0.8.0"}}})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ack") {
			var input map[string]string
			_ = json.NewDecoder(r.Body).Decode(&input)
			acknowledgements = append(acknowledgements, input["status"])
			_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cloud.Close()
	a := &agent{server: cloud.URL, client: cloud.Client(), updateSocket: path, state: credentialState{DeviceID: "device", DeviceSecret: "secret"}}
	if err := a.pollCommands(context.Background()); err != nil || len(acknowledgements) != 0 {
		t.Fatalf("updater running was acknowledged: acks=%#v error=%v", acknowledgements, err)
	}
	mu.Lock()
	completed = true
	mu.Unlock()
	if err := a.pollCommands(context.Background()); err != nil || len(acknowledgements) != 1 || acknowledgements[0] != "ok" {
		t.Fatalf("confirmed update was not acknowledged: acks=%#v error=%v", acknowledgements, err)
	}
}
