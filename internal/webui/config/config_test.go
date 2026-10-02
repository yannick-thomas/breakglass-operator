package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadFromEnv_Defaults(t *testing.T) {
	cfg := LoadFromEnv()

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.CookieName != "breakglass_session" {
		t.Errorf("expected default cookie name 'breakglass_session', got %s", cfg.CookieName)
	}
	if cfg.CookieSecret == "" {
		t.Error("expected auto-generated cookie secret, got empty")
	}
	if cfg.SessionTTL != 8*time.Hour {
		t.Errorf("expected 8h session TTL, got %v", cfg.SessionTTL)
	}
}

func TestLoadFromEnv_Custom(t *testing.T) {
	os.Setenv("WEBUI_PORT", "9090")
	os.Setenv("WEBUI_DEV_MODE", "true")
	os.Setenv("WEBUI_DEV_DEFAULT_USER", "custom-admin@corp.internal")
	defer func() {
		os.Unsetenv("WEBUI_PORT")
		os.Unsetenv("WEBUI_DEV_MODE")
		os.Unsetenv("WEBUI_DEV_DEFAULT_USER")
	}()

	cfg := LoadFromEnv()

	if cfg.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Port)
	}
	if !cfg.DevMode {
		t.Error("expected DevMode to be true")
	}
	if cfg.DevDefaultUser != "custom-admin@corp.internal" {
		t.Errorf("expected user 'custom-admin@corp.internal', got %s", cfg.DevDefaultUser)
	}
}
