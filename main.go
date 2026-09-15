package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"time"
)

var allowOrigin = getenv("ALLOW_ORIGIN", "*")

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("writeJSON: %v", err)
	}
}

// validAPIKey accepts the current API_SECRET or, during a rotation, the
// previous one (the rotator updates backend.env before frontend.env).
func validAPIKey(secrets *secretsFile, got string) bool {
	if got == "" {
		return false
	}
	for _, key := range []string{"API_SECRET", "API_SECRET_PREVIOUS"} {
		want := secrets.Get(key)
		if want != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			return true
		}
	}
	return false
}

func requireAPIKey(secrets *secretsFile, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validAPIKey(secrets, r.Header.Get("x-api-key")) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func requireSession(sessions *sessionStore, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		if _, ok := sessions.Get(c.Value); !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login required"})
			return
		}
		next(w, r)
	}
}

func corsAll(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowOrigin)
		w.Header().Set("Access-Control-Allow-Headers", "x-api-key, content-type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type postBody struct {
	Text string `json:"text"`
}

type loginBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type deps struct {
	db       *sql.DB
	crypto   *cryptoService
	secrets  *secretsFile
	auth     authenticator
	sessions *sessionStore
}

func newHandler(d deps) http.Handler {
	db, cs := d.db, d.crypto
	protected := func(h http.HandlerFunc) http.HandlerFunc {
		return requireAPIKey(d.secrets, requireSession(d.sessions, h))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("POST /api/login", requireAPIKey(d.secrets, func(w http.ResponseWriter, r *http.Request) {
		var body loginBody
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		user, err := d.auth.Authenticate(body.Username, body.Password)
		if errors.Is(err, errInvalidCredentials) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"authenticated": false, "error": err.Error()})
			return
		}
		if err != nil {
			log.Printf("login: %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "authentication service unavailable"})
			return
		}
		id, err := d.sessions.Create(user)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session failed"})
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookie,
			Value:    id,
			Path:     "/",
			MaxAge:   int(d.sessions.ttl.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			// ponytail: Secure: true once the gateway serves HTTPS
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"username":      user.Username,
			"displayName":   user.DisplayName,
			"mail":          user.Mail,
		})
	}))

	mux.HandleFunc("POST /api/logout", requireAPIKey(d.secrets, func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(sessionCookie); err == nil {
			d.sessions.Delete(c.Value)
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": false})
	}))

	mux.HandleFunc("GET /api/me", protected(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie(sessionCookie)
		user, _ := d.sessions.Get(c.Value)
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": true,
			"username":      user.Username,
			"displayName":   user.DisplayName,
			"mail":          user.Mail,
		})
	}))

	mux.HandleFunc("GET /api/data", protected(func(w http.ResponseWriter, r *http.Request) {
		ciphertext, err := latestRecord(db)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"message": "Protected data",
				"course":  "Security Exercise",
				"status":  "success",
			})
			return
		}
		plaintext, err := cs.Decrypt(ciphertext)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "decrypt failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"message":          plaintext,
			"ciphertext_in_db": ciphertext,
			"course":           "Security Exercise",
			"status":           "success",
		})
	}))

	mux.HandleFunc("POST /api/data", protected(func(w http.ResponseWriter, r *http.Request) {
		var body postBody
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Text == "" {
			body.Text = "POST received"
		}
		ciphertext, err := cs.Encrypt(body.Text)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "encrypt failed"})
			return
		}
		id, err := insertRecord(db, ciphertext)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "store failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"stored":     true,
			"id":         id,
			"ciphertext": ciphertext,
		})
	}))

	return corsAll(mux)
}

func main() {
	db, err := initDB(getenv("DB_PATH", "/data/app.db"))
	if err != nil {
		log.Fatalf("db init: %v", err)
	}
	defer db.Close()

	cs, err := newCryptoService(getenv("DATABASE_ENCRYPTION_KEY", "JabvrRXnraXsyPkZFSJmlrp2a9ROBuDkaiDs/TzIM2o="))
	if err != nil {
		log.Fatalf("crypto init: %v", err)
	}

	// API_SECRET and LDAP_BIND_PASSWORD are rotated every 2 minutes by the
	// external secret-rotator and re-read from this file on use.
	secrets := newSecretsFile(getenv("SECRETS_FILE", "/shared/backend.env"))

	auth := &ldapAuthenticator{
		url:     getenv("LDAP_URL", "ldap://host.docker.internal:389"),
		bindDN:  getenv("LDAP_BIND_DN", "cn=readonly,dc=example,dc=com"),
		usersDN: getenv("LDAP_USERS_DN", "ou=users,dc=example,dc=com"),
		secrets: secrets,
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, newHandler(deps{
		db:       db,
		crypto:   cs,
		secrets:  secrets,
		auth:     auth,
		sessions: newSessionStore(30 * time.Minute),
	})))
}
