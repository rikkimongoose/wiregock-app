package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func generateMockLoader() DataLoader {
	return MockLoader{map[string]string{}}
}

func mock(t *testing.T, body string) *MockData {
	var mockData MockData
	err := json.Unmarshal([]byte(body), &mockData)
	if err != nil {
		t.Fatalf(`Error parsing JSON format: %s`, err)
	}
	return &mockData
}

func mockFile(t *testing.T, fileName string) *MockData {
	byteValue, err := os.ReadFile(fileName)
	if err != nil {
		t.Fatalf(`Error loading file %s: %s`, fileName, err)
	}
	return mock(t, string(byteValue))
}

type TestTask struct {
	name       string
	mock       *MockData
	method     string
	body       string
	url        string
	headers    map[string]string
	cookies    map[string]string
	wantStatus int
	wantBody   string
}

func TestGenerateHandler(t *testing.T) {
	dataLoaderMock := generateMockLoader()

	tests := []TestTask{
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
			url:        "/",
			wantStatus: http.StatusOK,
			wantBody:   "Hello, world!",
		}, {
			name: "Successful GET request to /foo",
			mock: mock(t, `
						{
						    "request": { "urlPath": "/foo" },
						    "response": {
						        "body": "Hello, world!"
						    }
						}`),
			method:     http.MethodGet,
			body:       "",
			url:        "/foo",
			wantStatus: http.StatusOK,
			wantBody:   "Hello, world!",
		},
		{
			name: "Successful POST request",
			mock: mock(t, `
			{
			    "request": { "headers": { "Accept": { "contains": "xml" } } },
			    "response": {
			        "body": "Hello, world!"
			    }
			}`),
			method: http.MethodPost,
			body:   "",
			url:    "/",
			headers: map[string]string{
				"Test":   "test",
				"Accept": "Foo.xml",
			},
			wantStatus: http.StatusOK,
			wantBody:   "Hello, world!",
		},
		{
			name: "Successful GET request with params",
			mock: mock(t, `
{
    "request": { "queryParameters": { "foo": { "equalTo": "boo" } } },
    "response": {
        "body": "Hello, world!"
    }
}`),
			method:     http.MethodGet,
			body:       "",
			url:        "/?foo=boo",
			wantStatus: http.StatusOK,
			wantBody:   "Hello, world!",
		},
		{
			name: "Successful POST request with cookies",
			mock: mock(t, `
			{
			    "request": { "cookies": { "Accept": { "contains": "xml" } } },
			    "response": {
			        "body": "Hello, world!"
			    }
			}`),
			method: http.MethodPost,
			body:   "",
			url:    "/",
			cookies: map[string]string{
				"Test":   "test",
				"Accept": "Foo.xml",
			},
			wantStatus: http.StatusOK,
			wantBody:   "Hello, world!",
		},
	}
	logConfig := LogConfig{
		Encoding:         "json",
		OutputPaths:      []string{"stdout", "/tmp/logs"},
		ErrorOutputPaths: []string{"stderr"},
	}
	log := NewLogger(logConfig)
	mustacheService := MustacheService{dataLoaderMock, log}
	mocksHandler := MocksHandler{[]MockData{}, dataLoaderMock, mustacheService, MocksHandlerConfig{0}, log}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := mocksHandler.GenerateHandler(tt.mock)

			mux := http.NewServeMux()
			mux.Handle(removeQueryParamsSimple(tt.url), handler)

			server := httptest.NewServer(mux)
			defer server.Close()

			var reqBody = bytes.NewReader([]byte(tt.body))

			url := fmt.Sprintf("%s%s", server.URL, tt.url)

			switch tt.method {
			case http.MethodGet, http.MethodDelete:
				resp, err := http.Get(url)
				checkReponse(resp, &tt, t, err)
			case http.MethodPost, http.MethodPut:
				req, err := http.NewRequest(tt.method, url, reqBody)
				if err != nil {
					t.Fatalf("Failed to create request: %v", err)
				}
				for key, val := range tt.headers {
					req.Header.Add(key, val)
				}
				for key, val := range tt.cookies {
					req.AddCookie(&http.Cookie{
						Name:  key,
						Value: val,
					})
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("Failed to send request: %v", err)
				}
				defer resp.Body.Close()
			}
		})
	}
}

func checkReponse(resp *http.Response, tt *TestTask, t *testing.T, err error) {
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
}

func removeQueryParamsSimple(rawURL string) string {
	if i := strings.IndexByte(rawURL, '?'); i != -1 {
		return rawURL[:i]
	}
	return rawURL
}
