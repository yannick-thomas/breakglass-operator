package auth

import (
	"encoding/base64"
	"testing"
)

func TestGeneratePKCE(t *testing.T) {
	pkce, err := GeneratePKCE()
	if err != nil {
		t.Fatalf("GeneratePKCE failed: %v", err)
	}

	if pkce.Verifier == "" {
		t.Error("expected non-empty verifier")
	}
	if pkce.Challenge == "" {
		t.Error("expected non-empty challenge")
	}
	if pkce.Verifier == pkce.Challenge {
		t.Error("challenge should not equal verifier")
	}
}

func TestParseJWTClaims(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{
		"sub": "user-12345",
		"email": "engineer@company.com",
		"name": "Jane Engineer",
		"groups": ["sre", "on-call-prod"],
		"exp": 1999999999
	}`))
	fakeSignature := base64.RawURLEncoding.EncodeToString([]byte("signature-bytes"))

	jwt := header + "." + payload + "." + fakeSignature

	claims, err := parseJWTClaims(jwt)
	if err != nil {
		t.Fatalf("parseJWTClaims failed: %v", err)
	}

	if claims.Subject != "user-12345" {
		t.Errorf("expected subject user-12345, got %s", claims.Subject)
	}
	if claims.Email != "engineer@company.com" {
		t.Errorf("expected email engineer@company.com, got %s", claims.Email)
	}
	if claims.Name != "Jane Engineer" {
		t.Errorf("expected name Jane Engineer, got %s", claims.Name)
	}

	groups := claims.GetGroups()
	if len(groups) != 2 || groups[0] != "sre" || groups[1] != "on-call-prod" {
		t.Errorf("unexpected groups: %v", groups)
	}
}
