package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionIdleTimeout(t *testing.T) {
	if Defaults().SessionIdleTimeout != 0 {
		t.Fatal("idle timeout must default to off")
	}
	for _, tc := range []struct {
		idle, ttl string
		valid     bool
	}{
		{"0", "12h", true}, {"5m", "12h", true}, {"30m", "12h", true}, {"12h", "12h", true},
		{"4m59s", "12h", false}, {"12h1s", "12h", false}, {"-1s", "12h", false}, {"broken", "12h", false},
		{"30m", "10m", false}, {"30m", "48h", true}, {"720h", "720h", true},
	} {
		t.Run(tc.idle+"-"+tc.ttl, func(t *testing.T) {
			c, err := LoadFrom("", env(map[string]string{"SESSION_IDLE_TIMEOUT": tc.idle, "SESSION_TTL": tc.ttl}))
			if err == nil {
				err = errors.Join(c.validateProcess()...)
			}
			if tc.valid && err != nil {
				t.Fatalf("valid idle timeout: %v", err)
			}
			if !tc.valid && (err == nil || !strings.Contains(err.Error(), "SESSION_IDLE_TIMEOUT")) {
				t.Fatalf("want setting error, got %v", err)
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "sessions.yaml")
	if err := os.WriteFile(path, []byte("session_idle_timeout: 30m\nsession_ttl: 2h\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFrom(path, env(map[string]string{}))
	if err != nil || c.SessionIdleTimeout != 30*time.Minute || c.SessionTTL != 2*time.Hour {
		t.Fatalf("yaml: %+v %v", c, err)
	}
	c, err = LoadFrom(path, env(map[string]string{"SESSION_IDLE_TIMEOUT": "0"}))
	if err != nil || c.SessionIdleTimeout != 0 {
		t.Fatalf("override: %+v %v", c, err)
	}
}
