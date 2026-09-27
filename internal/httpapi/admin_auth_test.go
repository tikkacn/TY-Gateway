package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/store"
)

func TestAdminPasswordSessionLoginAndLogout(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "", []byte("0123456789abcdef0123456789abcdef"))
	srv.AdminPassword = "test-only-admin-password"

	login := httptest.NewRequest(http.MethodPost, "https://oec.example/api/v1/admin/login", strings.NewReader(`{"password":"test-only-admin-password"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "https://oec.example")
	login.RemoteAddr = "192.0.2.10:12345"
	loginResponse := httptest.NewRecorder()
	srv.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusOK {
		t.Fatalf("login status = %d, want %d: %s", loginResponse.Code, http.StatusOK, loginResponse.Body.String())
	}
	cookies := loginResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login set %d cookies, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != adminCookieName || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != int(adminSessionExpiry.Seconds()) {
		t.Fatalf("session cookie has unsafe attributes: %#v", cookie)
	}

	session := httptest.NewRequest(http.MethodGet, "https://oec.example/api/v1/admin/session", nil)
	session.AddCookie(cookie)
	sessionResponse := httptest.NewRecorder()
	srv.ServeHTTP(sessionResponse, session)
	if sessionResponse.Code != http.StatusOK || !strings.Contains(sessionResponse.Body.String(), `"authenticated":true`) {
		t.Fatalf("session check failed: status=%d body=%s", sessionResponse.Code, sessionResponse.Body.String())
	}

	logout := httptest.NewRequest(http.MethodPost, "https://oec.example/api/v1/admin/logout", strings.NewReader(`{}`))
	logout.Header.Set("Origin", "https://oec.example")
	logout.AddCookie(cookie)
	logoutResponse := httptest.NewRecorder()
	srv.ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d: %s", logoutResponse.Code, http.StatusNoContent, logoutResponse.Body.String())
	}

	afterLogout := httptest.NewRequest(http.MethodGet, "https://oec.example/api/v1/admin/session", nil)
	afterLogout.AddCookie(cookie)
	afterLogoutResponse := httptest.NewRecorder()
	srv.ServeHTTP(afterLogoutResponse, afterLogout)
	if afterLogoutResponse.Code != http.StatusOK || !strings.Contains(afterLogoutResponse.Body.String(), `"authenticated":false`) {
		t.Fatalf("revoked session still valid: status=%d body=%s", afterLogoutResponse.Code, afterLogoutResponse.Body.String())
	}
}

func TestAdminPasswordLoginRejectsWrongPasswordAndCrossOrigin(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "", []byte("0123456789abcdef0123456789abcdef"))
	srv.AdminPassword = "test-only-admin-password"

	for _, test := range []struct {
		name   string
		origin string
		body   string
		status int
	}{
		{name: "wrong password", origin: "https://oec.example", body: `{"password":"wrong"}`, status: http.StatusUnauthorized},
		{name: "cross origin", origin: "https://attacker.example", body: `{"password":"test-only-admin-password"}`, status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://oec.example/api/v1/admin/login", strings.NewReader(test.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", test.origin)
			req.RemoteAddr = "192.0.2.11:12345"
			response := httptest.NewRecorder()
			srv.ServeHTTP(response, req)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("rejected login unexpectedly set a cookie")
			}
		})
	}
}
