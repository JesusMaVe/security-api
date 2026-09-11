package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testSecret = "dev-secret-123"
const testEncryptionKey = "JabvrRXnraXsyPkZFSJmlrp2a9ROBuDkaiDs/TzIM2o="

func testHandler(t *testing.T) (http.Handler, *sql.DB) {
	setAPISecret(testSecret)
	db, err := initDB(":memory:")
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	cs, err := newCryptoService(testEncryptionKey)
	if err != nil {
		t.Fatalf("newCryptoService: %v", err)
	}
	return newHandler(db, cs), db
}

func do(h http.Handler, method, path, key, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if key != "" {
		req.Header.Set("x-api-key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	h, db := testHandler(t)
	defer db.Close()
	rec := do(h, http.MethodGet, "/health", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestGetData(t *testing.T) {
	h, db := testHandler(t)
	defer db.Close()
	if rec := do(h, http.MethodGet, "/api/data", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("Test 2: expected 401 without key, got %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/data", "wrong-key", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("Test 3: expected 401 with wrong key, got %d", rec.Code)
	}
	rec := do(h, http.MethodGet, "/api/data", testSecret, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("Test 4: expected 200 with correct key, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] != "Protected data" {
		t.Fatalf("Test 4: unexpected body %s", rec.Body.String())
	}
}

func TestPostThenGetRoundTrip(t *testing.T) {
	h, db := testHandler(t)
	defer db.Close()
	if rec := do(h, http.MethodPost, "/api/data", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without key, got %d", rec.Code)
	}

	postRec := do(h, http.MethodPost, "/api/data", testSecret, `{"text":"hello secrets"}`)
	if postRec.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct key, got %d: %s", postRec.Code, postRec.Body.String())
	}
	var postBody map[string]any
	if err := json.Unmarshal(postRec.Body.Bytes(), &postBody); err != nil || postBody["stored"] != true {
		t.Fatalf("unexpected post body %s", postRec.Body.String())
	}
	if postBody["ciphertext"] == "hello secrets" {
		t.Fatalf("ciphertext must not equal plaintext")
	}

	getRec := do(h, http.MethodGet, "/api/data", testSecret, "")
	if getRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", getRec.Code)
	}
	var getBody map[string]string
	if err := json.Unmarshal(getRec.Body.Bytes(), &getBody); err != nil || getBody["message"] != "hello secrets" {
		t.Fatalf("expected decrypted round-trip message, got %s", getRec.Body.String())
	}
}
