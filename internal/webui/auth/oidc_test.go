package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

// fakeProvider is a minimal OIDC provider that signs ID tokens with a test key.
type fakeProvider struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	claims func(grantType string) map[string]any
	// signWith overrides the signing key, to simulate a forged token.
	signWith *rsa.PrivateKey
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProvider{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                p.srv.URL,
			"authorization_endpoint":                p.srv.URL + "/authorize",
			"token_endpoint":                        p.srv.URL + "/token",
			"jwks_uri":                              p.srv.URL + "/jwks",
			"end_session_endpoint":                  p.srv.URL + "/logout",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access",
			"token_type":    "Bearer",
			"expires_in":    300,
			"refresh_token": "refresh-" + r.Form.Get("grant_type"),
			"id_token":      p.sign(p.claims(r.Form.Get("grant_type"))),
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) sign(claims map[string]any) string {
	key := p.key
	if p.signWith != nil {
		key = p.signWith
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		p.t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return raw
}

func (p *fakeProvider) validClaims(nonce string) map[string]any {
	return map[string]any{
		"iss":   p.srv.URL,
		"aud":   "breakglass",
		"sub":   "user-1",
		"name":  "Jane Engineer",
		"nonce": nonce,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
	}
}

func (p *fakeProvider) client(t *testing.T) *OIDCClient {
	t.Helper()
	c, err := NewOIDCClient(context.Background(), &config.Config{
		OIDCIssuerURL:   p.srv.URL,
		OIDCClientID:    "breakglass",
		OIDCRedirectURL: "https://breakglass.example.com/auth/callback",
		OIDCScopes:      []string{"openid"},
	})
	if err != nil {
		t.Fatalf("NewOIDCClient: %v", err)
	}
	return c
}

var pending = PendingLogin{Nonce: "nonce-1", PKCEVerifier: "verifier-verifier-verifier-verifier-verifier-1"}

func TestOIDC_ExchangeVerifiesToken(t *testing.T) {
	p := newFakeProvider(t)
	p.claims = func(string) map[string]any { return p.validClaims("nonce-1") }

	ts, err := p.client(t).Exchange(context.Background(), "code", pending)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if ts.Subject != "user-1" || ts.DisplayName != "Jane Engineer" || ts.RefreshToken == "" {
		t.Errorf("unexpected token set: %+v", ts)
	}
}

func TestOIDC_ExchangeRejectsInvalidTokens(t *testing.T) {
	forgeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]func(p *fakeProvider){
		"nonce mismatch": func(p *fakeProvider) {
			p.claims = func(string) map[string]any { return p.validClaims("other-nonce") }
		},
		"wrong audience": func(p *fakeProvider) {
			p.claims = func(string) map[string]any {
				c := p.validClaims("nonce-1")
				c["aud"] = "someone-else"
				return c
			}
		},
		"wrong issuer": func(p *fakeProvider) {
			p.claims = func(string) map[string]any {
				c := p.validClaims("nonce-1")
				c["iss"] = "https://evil.example.com"
				return c
			}
		},
		"expired": func(p *fakeProvider) {
			p.claims = func(string) map[string]any {
				c := p.validClaims("nonce-1")
				c["exp"] = time.Now().Add(-time.Minute).Unix()
				return c
			}
		},
		"forged signature": func(p *fakeProvider) {
			p.claims = func(string) map[string]any { return p.validClaims("nonce-1") }
			p.signWith = forgeKey
		},
	}

	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			p := newFakeProvider(t)
			setup(p)
			if _, err := p.client(t).Exchange(context.Background(), "code", pending); err == nil {
				t.Fatal("expected Exchange to reject the ID token")
			}
		})
	}
}

func TestOIDC_AuthCodeURLUsesPKCEAndNonce(t *testing.T) {
	p := newFakeProvider(t)
	u, err := url.Parse(p.client(t).AuthCodeURL("state-1", pending))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("state") != "state-1" || q.Get("nonce") != "nonce-1" ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		t.Errorf("unexpected auth URL parameters: %v", q)
	}
	if strings.Contains(u.String(), pending.PKCEVerifier) {
		t.Error("auth URL must not contain the PKCE verifier")
	}
}

func TestOIDC_BearerTokenRefreshes(t *testing.T) {
	p := newFakeProvider(t)
	p.claims = func(string) map[string]any { return p.validClaims("") }
	c := p.client(t)

	sess := NewSession(Identity{Username: "jane"}, "Jane", &TokenSet{
		Subject: "user-1", IDToken: "stale", Expiry: time.Now().Add(10 * time.Second), RefreshToken: "r1",
	}, time.Hour)

	token, err := c.BearerToken(context.Background(), sess)
	if err != nil {
		t.Fatalf("BearerToken: %v", err)
	}
	if token == "stale" {
		t.Error("expected the expiring token to be refreshed")
	}
	if sess.tokens.RefreshToken != "refresh-refresh_token" {
		t.Errorf("expected rotated refresh token, got %q", sess.tokens.RefreshToken)
	}
}

func TestOIDC_BearerTokenRejectsSubjectChange(t *testing.T) {
	p := newFakeProvider(t)
	p.claims = func(string) map[string]any {
		c := p.validClaims("")
		c["sub"] = "someone-else"
		return c
	}

	sess := NewSession(Identity{Username: "jane"}, "Jane", &TokenSet{
		Subject: "user-1", IDToken: "stale", Expiry: time.Now(), RefreshToken: "r1",
	}, time.Hour)

	if _, err := p.client(t).BearerToken(context.Background(), sess); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}

func TestOIDC_BearerTokenWithoutRefreshTokenExpires(t *testing.T) {
	p := newFakeProvider(t)
	sess := NewSession(Identity{Username: "jane"}, "Jane", &TokenSet{
		Subject: "user-1", IDToken: "stale", Expiry: time.Now(),
	}, time.Hour)

	if _, err := p.client(t).BearerToken(context.Background(), sess); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
}
