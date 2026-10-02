package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

func TestHandler_SecurityHeadersAndHealth(t *testing.T) {
	cfg := &config.Config{
		CookieSecret: "secret-key-for-unit-testing-32-chars!",
		DevMode:      true,
	}

	sm, _ := auth.NewSessionManager(cfg)
	mockFS := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<h1>BreakGlass</h1>")},
	}

	h := NewHandler(cfg, sm, nil, nil, mockFS)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Verify security headers
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing or incorrect X-Frame-Options header")
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing or incorrect X-Content-Type-Options header")
	}
	if w.Header().Get("Cache-Control") != "no-store, no-cache, must-revalidate, proxy-revalidate" {
		t.Errorf("missing or incorrect Cache-Control header")
	}
}

func TestHandler_DevLoginAndMeEndpoint(t *testing.T) {
	cfg := &config.Config{
		CookieSecret:     "secret-key-for-unit-testing-32-chars!",
		CookieName:       "bg_test_session",
		SessionTTL:       1 * time.Hour,
		DevMode:          true,
		DevDefaultUser:   "dev-user@example.com",
		DevDefaultGroups: "sre,on-call",
	}

	sm, _ := auth.NewSessionManager(cfg)
	h := NewHandler(cfg, sm, nil, nil, nil)

	// 1. Unauthenticated /api/v1/me should return 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	unauthW := httptest.NewRecorder()
	h.ServeHTTP(unauthW, unauthReq)

	if unauthW.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauth /api/v1/me, got %d", unauthW.Code)
	}

	// 2. Dev login
	loginReq := httptest.NewRequest(http.MethodGet, "/auth/dev-login?user=custom-dev@example.com", nil)
	loginW := httptest.NewRecorder()
	h.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusFound {
		t.Errorf("expected 302 redirect after dev login, got %d", loginW.Code)
	}

	cookie := loginW.Result().Cookies()[0]
	if cookie.Name != "bg_test_session" || cookie.Value == "" {
		t.Fatal("session cookie was not set")
	}

	// 3. Authenticated /api/v1/me
	authReq := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	authReq.AddCookie(cookie)
	authW := httptest.NewRecorder()
	h.ServeHTTP(authW, authReq)

	if authW.Code != http.StatusOK {
		t.Errorf("expected 200 for authenticated /api/v1/me, got %d", authW.Code)
	}

	var session auth.UserSession
	if err := json.NewDecoder(authW.Body).Decode(&session); err != nil {
		t.Fatalf("failed to decode me response: %v", err)
	}

	if session.Subject != "custom-dev@example.com" {
		t.Errorf("expected subject custom-dev@example.com, got %s", session.Subject)
	}
}
