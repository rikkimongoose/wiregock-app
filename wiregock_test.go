package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rikkimongoose/wiregock"
)

func generateMockLoader() DataLoader {
	return MockLoader{map[string]string{}}
}

func mock(t *testing.T, body string) *wiregock.MockData {
	var mockData wiregock.MockData
	err := json.Unmarshal([]byte(body), &mockData)
	if err != nil {
		t.Fatalf(`Error parsing JSON format: %s`, err)
	}
	return &mockData
}

func TestGenerateHandler(t *testing.T) {
	dataLoaderMock := generateMockLoader()

	tests := []struct {
		name       string
		mock       *wiregock.MockData
		method     string
		body       string
		wantStatus int
		wantBody   string
	}{
		{
			name: "Successful GET request",
			mock: mock(t, `
{
    "request": {},
    "response": {
        "body": "Hello, world!"
    }
}`),
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusOK,
			wantBody:   "Hello, world!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := GenerateHandler(tt.mock, dataLoaderMock)
			server := httptest.NewServer(handler)
			defer server.Close()

			var reqBody = bytes.NewReader([]byte(tt.body))

			req, err := http.NewRequest(tt.method, server.URL, reqBody)
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Failed to send request: %v", err)
			}
			defer resp.Body.Close()

			// Проверяем статус код.
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("Expected status %v, got %v", tt.wantStatus, resp.StatusCode)
			}

			// Проверяем тело ответа.
			body := make([]byte, len(tt.wantBody))
			_, err = resp.Body.Read(body)
			if err != nil && err.Error() != "EOF" {
				t.Fatalf("Failed to read response body: %v", err)
			}

			if string(body) != tt.wantBody {
				t.Errorf("Expected body %q, got %q", tt.wantBody, string(body))
			}
		})
	}
}
