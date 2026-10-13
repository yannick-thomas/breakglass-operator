package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration options for the BreakGlass WebUI service.
//
// The WebUI is a backend-for-frontend (BFF). It never holds a privileged
// Kubernetes identity: every write is sent with the signed-in person's own
// OIDC ID token, so the API server authenticates, authorizes, admits and
// audits that person. The pod's ServiceAccount is only a read-only facade for
// the privacy-filtered "my requests" and approval-inbox views.
type Config struct {
	// Server configuration
	ListenAddr      string
	Port            int
	TLSCertFile     string
	TLSKeyFile      string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// PublicURL is the externally visible origin of the WebUI. Unsafe
	// requests must carry exactly this Origin.
	PublicURL string

	// Session
	CookieName   string
	CookieSecure bool
	// SessionTTL is the absolute session lifetime. The session ends earlier
	// when the ID token expires and cannot be refreshed.
	SessionTTL time.Duration

	// OIDC Configuration
	OIDCEnabled      bool
	OIDCIssuerURL    string
	OIDCClientID     string
	OIDCClientSecret string `json:"-"` // Never log or serialize
	OIDCRedirectURL  string
	OIDCScopes       []string

	// DevMode runs the WebUI on a developer workstation. It signs the
	// developer in as the identity of their current kubeconfig context. It is
	// rejected in-cluster, together with OIDC, and on non-loopback addresses.
	DevMode bool

	// Kubernetes Client Configuration
	KubeconfigPath string
	InCluster      bool
}

// LoadFromEnv loads configuration from environment variables with safe defaults.
func LoadFromEnv() *Config {
	devMode := getEnvBool("WEBUI_DEV_MODE", false)
	defaultListen := "0.0.0.0"
	if devMode {
		defaultListen = "127.0.0.1"
	}

	cfg := &Config{
		ListenAddr:      getEnv("WEBUI_LISTEN_ADDR", defaultListen),
		Port:            getEnvInt("WEBUI_PORT", 8080),
		TLSCertFile:     getEnv("WEBUI_TLS_CERT", ""),
		TLSKeyFile:      getEnv("WEBUI_TLS_KEY", ""),
		ReadTimeout:     getEnvDuration("WEBUI_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:    getEnvDuration("WEBUI_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:     getEnvDuration("WEBUI_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout: getEnvDuration("WEBUI_SHUTDOWN_TIMEOUT", 10*time.Second),

		PublicURL: getEnv("WEBUI_PUBLIC_URL", ""),

		CookieName:   getEnv("WEBUI_COOKIE_NAME", "breakglass_session"),
		CookieSecure: getEnvBool("WEBUI_COOKIE_SECURE", !devMode),
		SessionTTL:   getEnvDuration("WEBUI_SESSION_TTL", 4*time.Hour),

		OIDCEnabled:      getEnvBool("WEBUI_OIDC_ENABLED", !devMode),
		OIDCIssuerURL:    getEnv("WEBUI_OIDC_ISSUER_URL", ""),
		OIDCClientID:     getEnv("WEBUI_OIDC_CLIENT_ID", ""),
		OIDCClientSecret: getEnv("WEBUI_OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:  getEnv("WEBUI_OIDC_REDIRECT_URL", ""),
		OIDCScopes:       getEnvSlice("WEBUI_OIDC_SCOPES", []string{"openid", "profile", "email", "groups", "offline_access"}),

		DevMode: devMode,

		KubeconfigPath: getEnv("KUBECONFIG", ""),
		InCluster:      getEnvBool("WEBUI_IN_CLUSTER", false),
	}

	if cfg.PublicURL == "" {
		if cfg.DevMode {
			cfg.PublicURL = fmt.Sprintf("http://localhost:%d", cfg.Port)
		} else if u, err := url.Parse(cfg.OIDCRedirectURL); err == nil && u.Host != "" {
			cfg.PublicURL = u.Scheme + "://" + u.Host
		}
	}

	return cfg
}

// Validate rejects configurations that would weaken the identity boundary.
func (c *Config) Validate() error {
	var errs []error

	if c.DevMode {
		if c.InCluster {
			errs = append(errs, errors.New("WEBUI_DEV_MODE must not be used in-cluster"))
		}
		if c.OIDCEnabled {
			errs = append(errs, errors.New("WEBUI_DEV_MODE and WEBUI_OIDC_ENABLED are mutually exclusive"))
		}
		if !isLoopback(c.ListenAddr) {
			errs = append(errs, fmt.Errorf("WEBUI_DEV_MODE requires a loopback WEBUI_LISTEN_ADDR, got %q", c.ListenAddr))
		}
	} else {
		if !c.OIDCEnabled {
			errs = append(errs, errors.New("WEBUI_OIDC_ENABLED is required outside of WEBUI_DEV_MODE"))
		}
		if c.OIDCIssuerURL == "" || c.OIDCClientID == "" || c.OIDCRedirectURL == "" {
			errs = append(errs, errors.New("WEBUI_OIDC_ISSUER_URL, WEBUI_OIDC_CLIENT_ID and WEBUI_OIDC_REDIRECT_URL are required"))
		}
		if !c.CookieSecure {
			errs = append(errs, errors.New("WEBUI_COOKIE_SECURE must not be disabled outside of WEBUI_DEV_MODE"))
		}
		if u, err := url.Parse(c.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" {
			errs = append(errs, fmt.Errorf("WEBUI_PUBLIC_URL must be an https origin, got %q", c.PublicURL))
		}
	}

	if c.SessionTTL <= 0 {
		errs = append(errs, errors.New("WEBUI_SESSION_TTL must be positive"))
	}

	return errors.Join(errs...)
}

func isLoopback(addr string) bool {
	if addr == "localhost" {
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
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
