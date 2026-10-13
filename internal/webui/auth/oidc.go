package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

// refreshSkew renews the ID token shortly before it expires, so that a
// Kubernetes call never starts with a token that expires in flight.
const refreshSkew = time.Minute

// OIDCClient runs the Authorization Code flow with PKCE and verifies every
// ID token (signature, issuer, audience, expiry and nonce) before it is used.
//
// The ID token is forwarded to the Kubernetes API server as a bearer token.
// The API server must therefore trust the same issuer with the WebUI client
// ID as audience (structured AuthenticationConfiguration or --oidc-* flags).
type OIDCClient struct {
	oauth         oauth2.Config
	verifier      *oidc.IDTokenVerifier
	endSessionURL string
}

type idTokenClaims struct {
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
}

// NewOIDCClient performs OIDC discovery. go-oidc rejects a discovery document
// whose issuer differs from the configured issuer.
func NewOIDCClient(ctx context.Context, cfg *config.Config) (*OIDCClient, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC provider %s: %w", cfg.OIDCIssuerURL, err)
	}

	var metadata struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("decode OIDC provider metadata: %w", err)
	}

	return &OIDCClient{
		oauth: oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       cfg.OIDCScopes,
		},
		verifier:      provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
		endSessionURL: metadata.EndSessionEndpoint,
	}, nil
}

// AuthCodeURL returns the provider login URL for one pending login.
func (c *OIDCClient) AuthCodeURL(state string, p PendingLogin) string {
	return c.oauth.AuthCodeURL(state,
		oidc.Nonce(p.Nonce),
		oauth2.S256ChallengeOption(p.PKCEVerifier),
	)
}

// Exchange redeems an authorization code and verifies the resulting ID token.
func (c *OIDCClient) Exchange(ctx context.Context, code string, p PendingLogin) (*TokenSet, error) {
	token, err := c.oauth.Exchange(ctx, code, oauth2.VerifierOption(p.PKCEVerifier))
	if err != nil {
		return nil, fmt.Errorf("exchange authorization code: %w", err)
	}
	ts, nonce, err := c.verify(ctx, token)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(nonce), []byte(p.Nonce)) != 1 {
		return nil, errors.New("ID token nonce does not match the login request")
	}
	return ts, nil
}

// BearerToken returns a valid ID token for the session, refreshing it when it
// is about to expire. A failed refresh ends the session.
func (c *OIDCClient) BearerToken(ctx context.Context, s *Session) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.tokens == nil {
		return "", errors.New("session has no OIDC credential")
	}
	if time.Until(s.tokens.Expiry) > refreshSkew {
		return s.tokens.IDToken, nil
	}
	if s.tokens.RefreshToken == "" {
		return "", ErrSessionExpired
	}

	src := c.oauth.TokenSource(ctx, &oauth2.Token{RefreshToken: s.tokens.RefreshToken})
	token, err := src.Token()
	if err != nil {
		return "", fmt.Errorf("%w: refresh ID token: %v", ErrSessionExpired, err)
	}
	ts, _, err := c.verify(ctx, token)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSessionExpired, err)
	}
	if ts.Subject != s.tokens.Subject {
		return "", fmt.Errorf("%w: refreshed ID token belongs to a different subject", ErrSessionExpired)
	}
	if ts.RefreshToken == "" {
		ts.RefreshToken = s.tokens.RefreshToken
	}
	s.tokens = ts
	return ts.IDToken, nil
}

// LogoutURL returns the provider's RP-initiated logout URL, or "" when the
// provider does not advertise one.
func (c *OIDCClient) LogoutURL(s *Session, postLogoutRedirect string) string {
	if c.endSessionURL == "" {
		return ""
	}
	u, err := url.Parse(c.endSessionURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("client_id", c.oauth.ClientID)
	q.Set("post_logout_redirect_uri", postLogoutRedirect)
	s.mu.Lock()
	if s.tokens != nil {
		q.Set("id_token_hint", s.tokens.IDToken)
	}
	s.mu.Unlock()
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *OIDCClient) verify(ctx context.Context, token *oauth2.Token) (*TokenSet, string, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, "", errors.New("token response contains no ID token")
	}
	idToken, err := c.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, "", fmt.Errorf("verify ID token: %w", err)
	}

	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, "", fmt.Errorf("decode ID token claims: %w", err)
	}
	displayName := claims.Name
	if displayName == "" {
		displayName = claims.PreferredUsername
	}
	if displayName == "" {
		displayName = claims.Email
	}

	return &TokenSet{
		Subject:      idToken.Subject,
		IDToken:      rawIDToken,
		Expiry:       idToken.Expiry,
		RefreshToken: token.RefreshToken,
		DisplayName:  displayName,
	}, idToken.Nonce, nil
}
