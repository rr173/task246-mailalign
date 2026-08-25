package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"task246-mailalign/internal/model"
	"task246-mailalign/internal/service"
	"task246-mailalign/internal/store"
)

func TestAnalyzeEndpointRequiresDKIMDomainAndSelector(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repository.Close()
	svc := service.New(repository)
	server := New(svc)
	request := func(method, path string, value any) *httptest.ResponseRecorder {
		data, _ := json.Marshal(value)
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, req)
		return response
	}
	response := request(http.MethodPost, "/api/samples", model.MessageSample{VisibleFrom: "a@example.com", ReturnPath: "b@example.net", RecipientIP: "192.0.2.2", Body: "x"})
	if response.Code != http.StatusCreated {
		t.Fatalf("create sample: %d %s", response.Code, response.Body.String())
	}
}
