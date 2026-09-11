package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
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

func requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("x-api-key")
		want := getAPISecret()
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
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

func newHandler(db *sql.DB, cs *cryptoService) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /api/data", requireAPIKey(func(w http.ResponseWriter, r *http.Request) {
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

	mux.HandleFunc("POST /api/data", requireAPIKey(func(w http.ResponseWriter, r *http.Request) {
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

	startRotation(
		getenv("API_SECRET", "lab-rotate-me"),
		2*time.Minute,
		getenv("SECRET_SHARE_PATH", "/shared/api_secret.env"),
	)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("listening on :" + port)
	log.Fatal(http.ListenAndServe(":"+port, newHandler(db, cs)))
}
