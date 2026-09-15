package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testSecret = "dev-secret-123"
const testEncryptionKey = "JabvrRXnraXsyPkZFSJmlrp2a9ROBuDkaiDs/TzIM2o="

// fakeAuth is an in-memory directory seeded with alice/alice123.
type fakeAuth struct {
	passwords map[string]string
	users     map[string]ldapUser
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{
		passwords: map[string]string{"alice": "alice123"},
		users:     map[string]ldapUser{"alice": {Username: "alice", DisplayName: "Alice Smith", Mail: "alice@example.com"}},
	}
}

func (f *fakeAuth) Authenticate(username, password string) (ldapUser, error) {
	if pw, ok := f.passwords[username]; ok && password != "" && pw == password {
		return f.users[username], nil
	}
	return ldapUser{}, errInvalidCredentials
}

func (f *fakeAuth) Register(u newUser) (ldapUser, error) {
	if _, ok := f.users[u.Username]; ok {
		return ldapUser{}, errUserExists
	}
	user := ldapUser{Username: u.Username, DisplayName: u.GivenName + " " + u.Surname, Mail: u.Mail}
	f.passwords[u.Username], f.users[u.Username] = u.Password, user
	return user, nil
}

func writeSecrets(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write secrets: %v", err)
	}
}

func testHandler(t *testing.T) (http.Handler, *sql.DB, string) {
	secretsPath := filepath.Join(t.TempDir(), "backend.env")
	writeSecrets(t, secretsPath, "export API_SECRET="+testSecret+"\nexport API_SECRET_PREVIOUS=\n")
	db, err := initDB(":memory:")
	if err != nil {
		t.Fatalf("initDB: %v", err)
	}
	cs, err := newCryptoService(testEncryptionKey)
	if err != nil {
		t.Fatalf("newCryptoService: %v", err)
	}
	h := newHandler(deps{
		db:       db,
		crypto:   cs,
		secrets:  newSecretsFile(secretsPath),
		auth:     newFakeAuth(),
		sessions: newSessionStore(time.Minute),
	})
	return h, db, secretsPath
}

func do(h http.Handler, method, path, key, cookie, body string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if key != "" {
		req.Header.Set("x-api-key", key)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func login(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := do(h, http.MethodPost, "/api/login", testSecret, "", `{"username":"alice","password":"alice123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			if !c.HttpOnly {
				t.Fatalf("session cookie must be HttpOnly")
			}
			return c.Value
		}
	}
	t.Fatalf("login: no session cookie")
	return ""
}

func TestHealth(t *testing.T) {
	h, db, _ := testHandler(t)
	defer db.Close()
	rec := do(h, http.MethodGet, "/health", "", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestLogin(t *testing.T) {
	h, db, _ := testHandler(t)
	defer db.Close()

	if rec := do(h, http.MethodPost, "/api/login", "", "", `{"username":"alice","password":"alice123"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without api key, got %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/login", testSecret, "", `{"username":"alice","password":"wrong"}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with bad password, got %d", rec.Code)
	}

	sid := login(t, h)
	rec := do(h, http.MethodGet, "/api/me", testSecret, sid, "")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK || body["username"] != "alice" {
		t.Fatalf("me: unexpected %d %s", rec.Code, rec.Body.String())
	}

	if rec := do(h, http.MethodPost, "/api/logout", testSecret, sid, ""); rec.Code != http.StatusOK {
		t.Fatalf("logout: expected 200, got %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/me", testSecret, sid, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("me after logout: expected 401, got %d", rec.Code)
	}
}

func TestRegister(t *testing.T) {
	h, db, _ := testHandler(t)
	defer db.Close()
	valid := `{"username":"Carol","password":"carol-pass-1","givenName":"Carol","sn":"Diaz","mail":"carol@example.com"}`

	if rec := do(h, http.MethodPost, "/api/register", "", "", valid); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without api key, got %d", rec.Code)
	}

	for name, body := range map[string]string{
		"bad username": `{"username":"x*","password":"carol-pass-1","givenName":"C","sn":"D","mail":"c@example.com"}`,
		"dn injection": `{"username":"carol,ou=groups","password":"carol-pass-1","givenName":"C","sn":"D","mail":"c@example.com"}`,
		"short pass":   `{"username":"carol","password":"short","givenName":"C","sn":"D","mail":"c@example.com"}`,
		"missing name": `{"username":"carol","password":"carol-pass-1","givenName":" ","sn":"D","mail":"c@example.com"}`,
		"bad mail":     `{"username":"carol","password":"carol-pass-1","givenName":"C","sn":"D","mail":"not-an-email"}`,
		"invalid json": `{`,
	} {
		if rec := do(h, http.MethodPost, "/api/register", testSecret, "", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}

	rec := do(h, http.MethodPost, "/api/register", testSecret, "", valid)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["username"] != "carol" {
		t.Fatalf("register: username should be normalized to lowercase, got %s", rec.Body.String())
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sid = c.Value
		}
	}
	if rec := do(h, http.MethodGet, "/api/data", testSecret, sid, ""); rec.Code != http.StatusOK {
		t.Fatalf("register should log the user in, got %d", rec.Code)
	}

	if rec := do(h, http.MethodPost, "/api/register", testSecret, "", valid); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate: expected 409, got %d", rec.Code)
	}
	if rec := do(h, http.MethodPost, "/api/login", testSecret, "", `{"username":"carol","password":"carol-pass-1"}`); rec.Code != http.StatusOK {
		t.Fatalf("login as registered user: expected 200, got %d", rec.Code)
	}
}

func TestSSHAHash(t *testing.T) {
	a, _ := sshaHash("secret")
	b, _ := sshaHash("secret")
	if !strings.HasPrefix(a, "{SSHA}") || a == b || strings.Contains(a, "secret") {
		t.Fatalf("expected salted {SSHA} hashes, got %q and %q", a, b)
	}
}

func TestGetData(t *testing.T) {
	h, db, _ := testHandler(t)
	defer db.Close()
	sid := login(t, h)

	if rec := do(h, http.MethodGet, "/api/data", "", sid, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without key, got %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/data", "wrong-key", sid, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong key, got %d", rec.Code)
	}
	if rec := do(h, http.MethodGet, "/api/data", testSecret, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", rec.Code)
	}
	rec := do(h, http.MethodGet, "/api/data", testSecret, sid, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with key and session, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["message"] != "Protected data" {
		t.Fatalf("unexpected body %s", rec.Body.String())
	}
}

func TestPostThenGetRoundTrip(t *testing.T) {
	h, db, _ := testHandler(t)
	defer db.Close()
	sid := login(t, h)

	postRec := do(h, http.MethodPost, "/api/data", testSecret, sid, `{"text":"hello secrets"}`)
	if postRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", postRec.Code, postRec.Body.String())
	}
	var postBody map[string]any
	if err := json.Unmarshal(postRec.Body.Bytes(), &postBody); err != nil || postBody["stored"] != true {
		t.Fatalf("unexpected post body %s", postRec.Body.String())
	}
	if postBody["ciphertext"] == "hello secrets" {
		t.Fatalf("ciphertext must not equal plaintext")
	}

	getRec := do(h, http.MethodGet, "/api/data", testSecret, sid, "")
	var getBody map[string]string
	if err := json.Unmarshal(getRec.Body.Bytes(), &getBody); err != nil || getBody["message"] != "hello secrets" {
		t.Fatalf("expected decrypted round-trip message, got %s", getRec.Body.String())
	}
}

func TestRotationKeepsSessionAndAcceptsPreviousKey(t *testing.T) {
	h, db, secretsPath := testHandler(t)
	defer db.Close()
	sid := login(t, h)

	// what secret-rotator writes: new key + grace for the old one
	writeSecrets(t, secretsPath, "export API_SECRET=rotated-456\nexport API_SECRET_PREVIOUS="+testSecret+"\n")
	future := time.Now().Add(time.Second)
	os.Chtimes(secretsPath, future, future)

	for _, key := range []string{"rotated-456", testSecret} {
		if rec := do(h, http.MethodGet, "/api/data", key, sid, ""); rec.Code != http.StatusOK {
			t.Fatalf("key %q after rotation: expected 200, got %d", key, rec.Code)
		}
	}

	// next rotation: the original key is no longer valid
	writeSecrets(t, secretsPath, "export API_SECRET=rotated-789\nexport API_SECRET_PREVIOUS=rotated-456\n")
	future = future.Add(time.Second)
	os.Chtimes(secretsPath, future, future)
	if rec := do(h, http.MethodGet, "/api/data", testSecret, sid, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale key: expected 401, got %d", rec.Code)
	}
}
