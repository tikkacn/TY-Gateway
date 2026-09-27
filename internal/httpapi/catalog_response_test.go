package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"tygateway/internal/store"
)

func TestAdminCatalogRoutesReturnOneJSONDocument(t *testing.T) {
	srv := NewServer(store.NewMemoryStore(), "admin-test", []byte("0123456789abcdef0123456789abcdef"))
	for _, path := range []string{"/api/v1/admin/provider-catalog", "/api/v1/admin/rule-packages"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Header.Set("X-TY-Admin-Token", "admin-test")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
				t.Fatalf("response is not a single JSON document: %v", err)
			}
		})
	}
}
