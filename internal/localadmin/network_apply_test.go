package localadmin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddressApplySessionAndDestination(t *testing.T) {
	dir, err := os.MkdirTemp("", "tynet-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "s")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			func() {
				defer c.Close()
				var request map[string]string
				if json.NewDecoder(c).Decode(&request) != nil {
					return
				}
				result := networkApplyResult{Phase: "queued", TargetIP: "10.23.42.10"}
				if request["action"] == "confirm" {
					if request["local_ip"] != "10.23.42.10" {
						result.Error = "wrong destination"
					} else {
						result.Phase = "committed"
					}
				}
				_ = json.NewEncoder(c).Encode(result)
			}()
		}
	}()
	s := testServer(t, false)
	s.cfg.NetworkSocket = socket
	setup := call(t, s, "POST", "/api/setup", `{"password":"correct horse battery staple"}`, nil, "10.23.42.2:1000")
	cookie := setup.Result().Cookies()[0]
	plan := `{"address_cidr":"10.23.42.10/24","gateway":"10.23.42.1","dns_mode":"router"}`
	for _, path := range []string{"/api/network/apply", "/api/network/apply/confirm"} {
		if response := call(t, s, "POST", path, plan, nil, "10.23.42.2:1000"); response.Code != 401 {
			t.Fatal(response.Code)
		}
	}
	if response := call(t, s, "POST", "/api/network/apply", plan, cookie, "10.23.42.2:1000"); response.Code != 409 {
		t.Fatal(response.Code)
	}
	if response := call(t, s, "PUT", "/api/network/settings", `{"plan":`+plan+`,"reservations":[]}`, cookie, "10.23.42.2:1000"); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	// Cross-origin attempts must be rejected even with a valid session.
	req := httptest.NewRequest("POST", "http://feiliu.local:8088/api/network/apply", strings.NewReader(plan))
	req.RemoteAddr = "10.23.42.2:1000"
	req.Header.Set("Origin", "http://attacker.invalid")
	req.AddCookie(cookie)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	response := call(t, s, "POST", "/api/network/apply", plan, cookie, "10.23.42.2:1000")
	if response.Code != 202 {
		t.Fatal(response.Code, response.Body.String())
	}
	if response := call(t, s, "GET", "/api/session", "", cookie, "10.23.42.2:1000"); response.Code != 401 {
		t.Fatal("old session survived apply")
	}
	login := call(t, s, "POST", "/api/login", `{"password":"correct horse battery staple"}`, nil, "10.23.42.2:1000")
	cookie = login.Result().Cookies()[0]
	for _, tc := range []struct {
		ip   string
		code int
	}{{"", 403}, {"10.23.42.211", 409}, {"10.23.42.10", 200}} {
		req := httptest.NewRequest("POST", "http://10.23.42.10:8088/api/network/apply/confirm", strings.NewReader(`{}`))
		req.RemoteAddr = "10.23.42.2:1000"
		req.AddCookie(cookie)
		req.Header.Set("Origin", "http://10.23.42.10:8088")
		req.Header.Set("X-Forwarded-Host", "10.23.42.10:8088")
		if tc.ip != "" {
			req = req.WithContext(context.WithValue(req.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 8088}))
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != tc.code {
			t.Fatal(tc.ip, w.Code, w.Body.String())
		}
	}
}
