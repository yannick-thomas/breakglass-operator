package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

// OIDCDiscoveryResponse holds standard OpenID Connect discovery endpoints.
type OIDCDiscoveryResponse struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSUri               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

// TokenResponse represents the OAuth2 / OIDC token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
}

// IDTokenClaims holds standard claims parsed from the JWT payload.
type IDTokenClaims struct {
	Subject           string      `json:"sub"`
	Email             string      `json:"email"`
	EmailVerified     bool        `json:"email_verified"`
	Name              string      `json:"name"`
	PreferredUsername string      `json:"preferred_username"`
	Groups            interface{} `json:"groups"` // Can be []string or string in various IdPs
	Expiry            int64       `json:"exp"`
	IssuedAt          int64       `json:"iat"`
	Issuer            string      `json:"iss"`
	Audience          interface{} `json:"aud"`
}

// GetGroups extracts a string slice of groups from claims.
func (c *IDTokenClaims) GetGroups() []string {
	if c.Groups == nil {
		return nil
	}
	switch v := c.Groups.(type) {
	case []interface{}:
		var result []string
		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return v
	case string:
		return strings.Split(v, ",")
	default:
		return nil
	}
}

// OIDCClient handles authentication against standard OpenID Connect Identity Providers.
type OIDCClient struct {
	cfg        *config.Config
	httpClient *http.Client
	discovery  *OIDCDiscoveryResponse
}

// NewOIDCClient initializes and performs discovery if OIDC is enabled.
func NewOIDCClient(ctx context.Context, cfg *config.Config) (*OIDCClient, error) {
	client := &OIDCClient{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	if cfg.OIDCEnabled && cfg.OIDCIssuerURL != "" {
		discoveryURL := strings.TrimSuffix(cfg.OIDCIssuerURL, "/") + "/.well-known/openid-configuration"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create discovery request: %w", err)
		}

		resp, err := client.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("perform OIDC discovery on %s: %w", discoveryURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
		}

		var disco OIDCDiscoveryResponse
		if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil {
			return nil, fmt.Errorf("decode discovery response: %w", err)
		}
		client.discovery = &disco
	}

	return client, nil
}

// PKCEPair holds the verifier and challenge for Authorization Code with PKCE.
type PKCEPair struct {
	Verifier  string
	Challenge string
}

// GeneratePKCE creates a secure cryptographic random PKCE verifier and S256 challenge.
func GeneratePKCE() (*PKCEPair, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("generate random bytes: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(bytes)

	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCEPair{
		Verifier:  verifier,
		Challenge: challenge,
	}, nil
}

// GenerateState creates a secure state string for CSRF protection.
func GenerateState() (string, error) {
	bytes := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GetAuthURL generates the login redirect URL for the OIDC provider.
func (c *OIDCClient) GetAuthURL(state, challenge string) (string, error) {
	if c.discovery == nil || c.discovery.AuthorizationEndpoint == "" {
		return "", errors.New("OIDC authorization endpoint is not configured")
	}

	u, err := url.Parse(c.discovery.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("parse auth endpoint: %w", err)
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.OIDCClientID)
	q.Set("redirect_uri", c.cfg.OIDCRedirectURL)
	q.Set("scope", strings.Join(c.cfg.OIDCScopes, " "))
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// ExchangeCode trades an authorization code for tokens and extracts user claims.
func (c *OIDCClient) ExchangeCode(ctx context.Context, code, verifier string) (*UserSession, error) {
	if c.discovery == nil || c.discovery.TokenEndpoint == "" {
		return nil, errors.New("OIDC token endpoint is not configured")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", c.cfg.OIDCRedirectURL)
	form.Set("client_id", c.cfg.OIDCClientID)
	if c.cfg.OIDCClientSecret != "" {
		form.Set("client_secret", c.cfg.OIDCClientSecret)
	}
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	// Parse ID Token claims (JWT Payload)
	claims, err := parseJWTClaims(tokenResp.IDToken)
	if err != nil {
		return nil, fmt.Errorf("parse ID token: %w", err)
	}

	// Determine effective username / subject
	username := claims.Email
	if username == "" {
		username = claims.PreferredUsername
	}
	if username == "" {
		username = claims.Subject
	}

	displayName := claims.Name
	if displayName == "" {
		displayName = username
	}

	expiresAt := time.Now().Add(c.cfg.SessionTTL)
	if claims.Expiry > 0 {
		tokenExp := time.Unix(claims.Expiry, 0)
		if tokenExp.Before(expiresAt) {
			expiresAt = tokenExp
		}
	}

	return &UserSession{
		Subject:   username,
		Email:     claims.Email,
		Name:      displayName,
		Groups:    claims.GetGroups(),
		ExpiresAt: expiresAt,
		IDToken:   tokenResp.IDToken,
	}, nil
}

// parseJWTClaims parses the unverified payload part of a JWT to extract claims.
func parseJWTClaims(rawToken string) (*IDTokenClaims, error) {
	if rawToken == "" {
		return nil, errors.New("empty ID token")
	}

	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT: expected 3 parts")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}

	var claims IDTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}

	return &claims, nil
}
