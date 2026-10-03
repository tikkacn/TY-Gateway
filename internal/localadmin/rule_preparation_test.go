package localadmin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPublicRuleMenuBeforeAgentEnrollment(t *testing.T) {
	s := &Server{}
	w := httptest.NewRecorder()
	s.customerMe(w, httptest.NewRequest(http.MethodGet, "/api/customer/me", nil))
	var state struct {
		Pending  bool             `json:"initialization_pending"`
		Message  string           `json:"initialization_message"`
		Packages []map[string]any `json:"rule_packages"`
		Nodes    []any            `json:"nodes"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &state) != nil || !state.Pending || state.Message == "" || len(state.Packages) != 4 || len(state.Nodes) != 0 {
		t.Fatal("early public menu masked Agent failure or exposed nodes")
	}
}
