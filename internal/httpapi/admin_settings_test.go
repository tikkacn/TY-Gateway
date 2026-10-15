package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tygateway/internal/store"
)

func TestAdminSettingsOmitsObsoleteHardwarePlaceholder(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "admin", []byte("0123456789abcdef0123456789abcdef"))
	for _, path := range []string{"/admin", "/admin/"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("admin page status=%d", w.Code)
			}
			body := w.Body.String()
			for _, obsolete := range []string{"OEC integration", "等待硬件到货"} {
				if strings.Contains(body, obsolete) {
					t.Errorf("obsolete hardware placeholder remains: %s", obsolete)
				}
			}
			for _, retained := range []string{"id=\"page-settings\"", "服务信息", "安全状态", "Public endpoint", "API base", "Storage", "Service", "Listener"} {
				if !strings.Contains(body, retained) {
					t.Errorf("existing settings content missing: %s", retained)
				}
			}
		})
	}
}

