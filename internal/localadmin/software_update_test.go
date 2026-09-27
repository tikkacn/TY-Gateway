package localadmin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSoftwareUpdateRequiresSessionAndRejectsRequestParameters(t *testing.T) {
	s := testServer(t, false)
	remote := "10.23.43.50:5000"
	unauthorized := call(t, s, http.MethodPost, "/api/software/apply", "", nil, remote)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated apply status=%d", unauthorized.Code)
	}
	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, remote)
	cookie := setup.Result().Cookies()[0]
	withBody := call(t, s, http.MethodPost, "/api/software/apply", `{"url":"https://untrusted.invalid/"}`, cookie, remote)
	if withBody.Code != http.StatusBadRequest {
		t.Fatalf("arbitrary update parameters accepted: %d %s", withBody.Code, withBody.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "http://feiliu.local:8088/api/software/apply", nil)
	request.RemoteAddr = remote
	request.Host = "feiliu.local:8088"
	request.Header.Set("Origin", "http://attacker.invalid")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin update accepted: %d", response.Code)
	}
}

func TestSoftwareUpdateSocketUsesFixedActions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable on test host: %v", err)
	}
	defer listener.Close()
	s := testServer(t, false)
	s.cfg.UpdateSocket = path
	requests := make(chan string, 2)
	go func() {
		for i := 0; i < 2; i++ {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			var value map[string]string
			_ = json.NewDecoder(bufio.NewReader(conn)).Decode(&value)
			requests <- value["action"]
			if value["action"] == "status" {
				_, _ = conn.Write([]byte(`{"version":"1.2.3","updating":false}` + "\n"))
			} else {
				_, _ = conn.Write([]byte(`{"version":"1.2.4","update_available":true}` + "\n"))
			}
			_ = conn.Close()
		}
	}()
	remote := "10.23.43.50:5000"
	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, remote)
	cookie := setup.Result().Cookies()[0]
	status := call(t, s, http.MethodGet, "/api/software/status", "", cookie, remote)
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"version":"1.2.3"`) {
		t.Fatalf("status=%d body=%s", status.Code, status.Body.String())
	}
	check := call(t, s, http.MethodPost, "/api/software/check", "", cookie, remote)
	if check.Code != http.StatusOK || !strings.Contains(check.Body.String(), `"update_available":true`) {
		t.Fatalf("check=%d body=%s", check.Code, check.Body.String())
	}
	if first, second := <-requests, <-requests; first != "status" || second != "check" {
		t.Fatalf("unexpected socket actions %q %q", first, second)
	}
}

func TestOfflineSoftwareUploadRequiresSessionAndUsesFixedSignedPackageFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("Unix sockets unavailable on test host: %v", err)
	}
	defer listener.Close()
	s := testServer(t, false)
	s.cfg.UpdateSocket = path
	remote := "10.23.43.50:5000"
	unauthorizedBody, unauthorizedType := offlineForm(t, "pilot")
	unauthorizedRequest := httptest.NewRequest(http.MethodPost, "http://feiliu.local:8088/api/software/offline", unauthorizedBody)
	unauthorizedRequest.RemoteAddr = remote
	unauthorizedRequest.Host = "feiliu.local:8088"
	unauthorizedRequest.Header.Set("Origin", "http://feiliu.local:8088")
	unauthorizedRequest.Header.Set("Content-Type", unauthorizedType)
	unauthorized := httptest.NewRecorder()
	s.ServeHTTP(unauthorized, unauthorizedRequest)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated offline upload status=%d", unauthorized.Code)
	}

	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, remote)
	cookie := setup.Result().Cookies()[0]
	requests := make(chan map[string]string, 1)
	readErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			readErr <- acceptErr
			return
		}
		defer conn.Close()
		var request map[string]string
		if decodeErr := json.NewDecoder(bufio.NewReader(conn)).Decode(&request); decodeErr != nil {
			readErr <- decodeErr
			return
		}
		requests <- request
		dir := filepath.Join(s.cfg.StateDir, "offline-update", request["upload_id"])
		bundle, bundleErr := os.ReadFile(filepath.Join(dir, "release.json"))
		artifact, artifactErr := os.ReadFile(filepath.Join(dir, "ty-gateway-oec-overlay.tar.gz"))
		if bundleErr != nil || artifactErr != nil || string(bundle) != `{"signed":"bundle"}` || string(artifact) != "test-tarball" {
			readErr <- os.ErrInvalid
			return
		}
		_, _ = conn.Write([]byte(`{"started":true,"channel":"pilot"}` + "\n"))
	}()

	body, contentType := offlineForm(t, "pilot")
	request := httptest.NewRequest(http.MethodPost, "http://feiliu.local:8088/api/software/offline", body)
	request.RemoteAddr = remote
	request.Host = "feiliu.local:8088"
	request.Header.Set("Origin", "http://feiliu.local:8088")
	request.Header.Set("Content-Type", contentType)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"started":true`) {
		t.Fatalf("offline update response status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case err := <-readErr:
		t.Fatal(err)
	default:
	}
	forwarded := <-requests
	if forwarded["action"] != "apply-local" || forwarded["channel"] != "pilot" || len(forwarded["upload_id"]) != 32 {
		t.Fatalf("unexpected privileged request: %#v", forwarded)
	}
	entries, err := os.ReadDir(filepath.Join(s.cfg.StateDir, "offline-update"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary upload was not removed after handoff: entries=%v err=%v", entries, err)
	}
}

func TestOfflineSoftwareUploadRejectsInvalidChannelBeforeCallingRootService(t *testing.T) {
	s := testServer(t, false)
	setup := call(t, s, http.MethodPost, "/api/setup", `{"password":"correct horse battery staple"}`, nil, "10.23.43.50:5000")
	body, contentType := offlineForm(t, "other")
	request := httptest.NewRequest(http.MethodPost, "http://feiliu.local:8088/api/software/offline", body)
	request.RemoteAddr = "10.23.43.50:5000"
	request.Host = "feiliu.local:8088"
	request.Header.Set("Origin", "http://feiliu.local:8088")
	request.Header.Set("Content-Type", contentType)
	request.AddCookie(setup.Result().Cookies()[0])
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid channel status=%d body=%s", response.Code, response.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(s.cfg.StateDir, "offline-update"))
	if err == nil && len(entries) != 0 {
		t.Fatalf("invalid channel left upload data behind: entries=%v", entries)
	}
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("could not inspect temporary upload cleanup: %v", err)
	}
}

func offlineForm(t *testing.T, channel string) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("channel", channel); err != nil {
		t.Fatal(err)
	}
	bundle, err := writer.CreateFormFile("bundle", "release.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = bundle.Write([]byte(`{"signed":"bundle"}`))
	artifact, err := writer.CreateFormFile("artifact", "ty-gateway-oec-overlay.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = artifact.Write([]byte("test-tarball"))
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, writer.FormDataContentType()
}
