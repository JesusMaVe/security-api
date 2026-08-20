package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func do(method, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if key != "" {
		req.Header.Set("x-api-key", key)
	}
	rec := httptest.NewRecorder()
	newHandler().ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	rec := do(http.MethodGet, "/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestGetData(t *testing.T) {
	if rec := do(http.MethodGet, "/api/data", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("Test 2: expected 401 without key, got %d", rec.Code)
	}
	if rec := do(http.MethodGet, "/api/data", "wrong-key"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("Test 3: expected 401 with wrong key, got %d", rec.Code)
	}
	rec := do(http.MethodGet, "/api/data", "dev-secret-123")
	if rec.Code != http.StatusOK {
		t.Fatalf("Test 4: expected 200 with correct key, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] != "Protected data" {
		t.Fatalf("Test 4: unexpected body %s", rec.Body.String())
	}
}

func TestPostData(t *testing.T) {
	if rec := do(http.MethodPost, "/api/data", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("Test 5: expected 401 without key, got %d", rec.Code)
	}
	rec := do(http.MethodPost, "/api/data", "dev-secret-123")
	if rec.Code != http.StatusOK {
		t.Fatalf("Test 6: expected 200 with correct key, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] != "POST received" {
		t.Fatalf("Test 6: unexpected body %s", rec.Body.String())
	}
}