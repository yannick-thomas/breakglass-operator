package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration options for the BreakGlass WebUI service.
type Config struct {
	// Server configuration
	ListenAddr      string        `json:"listenAddr"`
	Port            int           `json:"port"`
	TLSCertFile     string        `json:"tlsCertFile"`
	TLSKeyFile      string        `json:"tlsKeyFile"`
	ReadTimeout     time.Duration `json:"readTimeout"`
	WriteTimeout    time.Duration `json:"writeTimeout"`
	IdleTimeout     time.Duration `json:"idleTimeout"`
	ShutdownTimeout time.Duration `json:"shutdownTimeout"`

	// Session & Security
	CookieSecret   string        `json:"-"` // Never log or serialize
	CookieName     string        `json:"cookieName"`
	CookieSecure   bool          `json:"cookieSecure"`
	SessionTTL     time.Duration `json:"sessionTTL"`
	AllowedOrigins []string      `json:"allowedOrigins"`

	// OIDC Configuration
	OIDCEnabled      bool     `json:"oidcEnabled"`
	OIDCIssuerURL    string   `json:"oidcIssuerURL"`
	OIDCClientID     string   `json:"oidcClientID"`
	OIDCClientSecret string   `json:"-"` // Never log or serialize
	OIDCRedirectURL  string   `json:"oidcRedirectURL"`
	OIDCScopes       []string `json:"oidcScopes"`

	// Dev / Demo Mode
	DevMode          bool   `json:"devMode"`
	DevDefaultUser   string `json:"devDefaultUser"`
	DevDefaultGroups string `json:"devDefaultGroups"`

	// Kubernetes Client Configuration
	KubeconfigPath string `json:"kubeconfigPath"`
	InCluster      bool   `json:"inCluster"`
}

// LoadFromEnv loads configuration from environment variables with safe defaults.
func LoadFromEnv() *Config {
	cfg := &Config{
		ListenAddr:      getEnv("WEBUI_LISTEN_ADDR", "0.0.0.0"),
		Port:            getEnvInt("WEBUI_PORT", 8080),
		TLSCertFile:     getEnv("WEBUI_TLS_CERT", ""),
		TLSKeyFile:      getEnv("WEBUI_TLS_KEY", ""),
		ReadTimeout:     getEnvDuration("WEBUI_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:    getEnvDuration("WEBUI_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:     getEnvDuration("WEBUI_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout: getEnvDuration("WEBUI_SHUTDOWN_TIMEOUT", 10*time.Second),

		CookieSecret:   getEnv("WEBUI_COOKIE_SECRET", ""),
		CookieName:     getEnv("WEBUI_COOKIE_NAME", "breakglass_session"),
		CookieSecure:   getEnvBool("WEBUI_COOKIE_SECURE", false),
		SessionTTL:     getEnvDuration("WEBUI_SESSION_TTL", 8*time.Hour),
		AllowedOrigins: getEnvSlice("WEBUI_ALLOWED_ORIGINS", []string{"*"}),

		OIDCEnabled:      getEnvBool("WEBUI_OIDC_ENABLED", false),
		OIDCIssuerURL:    getEnv("WEBUI_OIDC_ISSUER_URL", ""),
		OIDCClientID:     getEnv("WEBUI_OIDC_CLIENT_ID", ""),
		OIDCClientSecret: getEnv("WEBUI_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:  getEnv("WEBUI_OIDC_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		OIDCScopes:       getEnvSlice("WEBUI_OIDC_SCOPES", []string{"openid", "profile", "email", "groups"}),

		DevMode:          getEnvBool("WEBUI_DEV_MODE", false),
		DevDefaultUser:   getEnv("WEBUI_DEV_DEFAULT_USER", "admin@example.com"),
		DevDefaultGroups: getEnv("WEBUI_DEV_DEFAULT_GROUPS", "on-call,cluster-admins,breakglass-approvers"),

		KubeconfigPath: getEnv("KUBECONFIG", ""),
		InCluster:      getEnvBool("WEBUI_IN_CLUSTER", false),
	}

	// Auto-generate cookie secret if empty
	if cfg.CookieSecret == "" {
		randomBytes := make([]byte, 32)
		if _, err := rand.Read(randomBytes); err == nil {
			cfg.CookieSecret = hex.EncodeToString(randomBytes)
		} else {
			cfg.CookieSecret = "insecure-default-secret-please-change-in-production-32b"
		}
	}

	// In production (non-dev), ensure secure cookies if TLS is configured
	if cfg.TLSCertFile != "" && !cfg.DevMode {
		cfg.CookieSecure = true
	}

	return cfg
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return strings.TrimSpace(val)
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if intVal, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return intVal
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(val)); err == nil {
			return d
		}
	}
	return defaultVal
}

func getEnvSlice(key string, defaultVal []string) []string {
	if val := os.Getenv(key); val != "" {
		parts := strings.Split(val, ",")
		var cleaned []string
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				cleaned = append(cleaned, trimmed)
			}
		}
		if len(cleaned) > 0 {
			return cleaned
		}
	}
	return defaultVal
}
