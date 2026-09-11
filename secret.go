package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// currentSecret is the live API_SECRET value. It starts at the value
// injected via the API_SECRET env var and is regenerated on a fixed
// interval by startRotation, without needing a process restart.
var (
	secretMu      sync.RWMutex
	currentSecret string
)

func getAPISecret() string {
	secretMu.RLock()
	defer secretMu.RUnlock()
	return currentSecret
}

func setAPISecret(v string) {
	secretMu.Lock()
	currentSecret = v
	secretMu.Unlock()
}

func generateSecret() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// extremely unlikely; fall back to a timestamp-derived value
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// writeSharedSecret writes the current secret to a shell-sourceable file so
// other processes (the NGINX/OpenResty gateway, or `docker exec ... source
// ... && echo $API_SECRET` for demo purposes) can read the live value
// without the API container restarting.
func writeSharedSecret(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	content := fmt.Sprintf("export API_SECRET=%s\n", value)
	return os.WriteFile(path, []byte(content), 0644)
}

// startRotation sets the initial secret, publishes it immediately, then
// regenerates and republishes it every interval in the background.
func startRotation(initial string, interval time.Duration, sharePath string) {
	setAPISecret(initial)
	if err := writeSharedSecret(sharePath, initial); err != nil {
		log.Printf("secret rotation: initial write failed: %v", err)
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			next := generateSecret()
			setAPISecret(next)
			if err := writeSharedSecret(sharePath, next); err != nil {
				log.Printf("secret rotation: write failed: %v", err)
				continue
			}
			log.Println("API_SECRET rotated")
		}
	}()
}
