package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadFromEnv_ProductionDefaults(t *testing.T) {
	t.Setenv("WEBUI_OIDC_ISSUER_URL", "https://idp.example.com")
	t.Setenv("WEBUI_OIDC_CLIENT_ID", "breakglass")
	t.Setenv("WEBUI_OIDC_REDIRECT_URL", "https://breakglass.example.com/auth/callback")

	cfg := LoadFromEnv()

	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}
	if !cfg.OIDCEnabled || !cfg.CookieSecure || cfg.DevMode {
		t.Errorf("expected OIDC and secure cookies by default, got %+v", cfg)
	}
	if cfg.SessionTTL != 4*time.Hour {
		t.Errorf("expected 4h session TTL, got %v", cfg.SessionTTL)
	}
	if cfg.PublicURL != "https://breakglass.example.com" {
		t.Errorf("expected public URL derived from redirect URL, got %q", cfg.PublicURL)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid production config, got %v", err)
	}
}

func TestLoadFromEnv_DevModeDefaults(t *testing.T) {
	t.Setenv("WEBUI_DEV_MODE", "true")
	t.Setenv("WEBUI_PORT", "9090")

	cfg := LoadFromEnv()

	if cfg.ListenAddr != "127.0.0.1" || cfg.OIDCEnabled || cfg.CookieSecure {
		t.Errorf("unexpected dev defaults: %+v", cfg)
	}
	if cfg.PublicURL != "http://localhost:9090" {
		t.Errorf("unexpected dev public URL %q", cfg.PublicURL)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid dev config, got %v", err)
	}
}

func TestValidate_RejectsUnsafeConfigurations(t *testing.T) {
	valid := func() *Config {
		return &Config{
			OIDCEnabled:     true,
			OIDCIssuerURL:   "https://idp.example.com",
			OIDCClientID:    "breakglass",
			OIDCRedirectURL: "https://breakglass.example.com/auth/callback",
			PublicURL:       "https://breakglass.example.com",
			CookieSecure:    true,
			SessionTTL:      time.Hour,
		}
	}

	tests := map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"dev mode in-cluster": {
			mutate: func(c *Config) { c.DevMode, c.OIDCEnabled, c.InCluster, c.ListenAddr = true, false, true, "127.0.0.1" },
			want:   "in-cluster",
		},
		"dev mode on all interfaces": {
			mutate: func(c *Config) { c.DevMode, c.OIDCEnabled, c.ListenAddr = true, false, "0.0.0.0" },
			want:   "loopback",
		},
		"dev mode with OIDC": {
			mutate: func(c *Config) { c.DevMode, c.ListenAddr = true, "127.0.0.1" },
			want:   "mutually exclusive",
		},
		"no OIDC outside dev mode": {
			mutate: func(c *Config) { c.OIDCEnabled = false },
			want:   "WEBUI_OIDC_ENABLED",
		},
		"insecure cookies": {
			mutate: func(c *Config) { c.CookieSecure = false },
			want:   "WEBUI_COOKIE_SECURE",
		},
		"plain http public URL": {
			mutate: func(c *Config) { c.PublicURL = "http://breakglass.example.com" },
			want:   "https origin",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}
