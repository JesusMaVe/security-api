package main

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// secretsFile exposes the live values of a sourceable `export KEY=value` file
// (/shared/backend.env). The file is rewritten by the external secret-rotator
// every 2 minutes; it is re-parsed whenever its mtime or size changes, so a
// rotation takes effect without restarting the process.
type secretsFile struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64
	values  map[string]string
}

func newSecretsFile(path string) *secretsFile {
	return &secretsFile{path: path}
}

// Get returns the current value of key, falling back to the process
// environment when the file doesn't exist or doesn't define it.
func (s *secretsFile) Get(key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(false)
	if v, ok := s.values[key]; ok {
		return v
	}
	return os.Getenv(key)
}

// Reload forces a re-read, used when a credential was just rejected and the
// rotator may have rewritten the file within the same mtime granularity.
func (s *secretsFile) Reload() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked(true)
}

func (s *secretsFile) refreshLocked(force bool) {
	info, err := os.Stat(s.path)
	if err != nil {
		s.values = nil
		return
	}
	if !force && s.values != nil && info.ModTime().Equal(s.modTime) && info.Size() == s.size {
		return
	}
	values, err := parseEnvFile(s.path)
	if err != nil {
		log.Printf("secrets: read %s: %v", s.path, err)
		return
	}
	s.values, s.modTime, s.size = values, info.ModTime(), info.Size()
}

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	values := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return values, sc.Err()
}
