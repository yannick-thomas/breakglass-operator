package auth

import (
	"testing"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

func TestSessionManager_EncryptDecrypt(t *testing.T) {
	cfg := &config.Config{
		CookieSecret: "my-very-secret-test-key-32-chars-long!",
		CookieName:   "bg_test_session",
		SessionTTL:   1 * time.Hour,
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	session := &UserSession{
		Subject:   "test-user@example.com",
		Email:     "test-user@example.com",
		Name:      "Test User",
		Groups:    []string{"on-call", "sre-team"},
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	encrypted, err := sm.Encrypt(session)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if encrypted == "" {
		t.Fatal("encrypted string is empty")
	}

	decrypted, err := sm.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if decrypted.Subject != session.Subject {
		t.Errorf("expected subject %q, got %q", session.Subject, decrypted.Subject)
	}
	if decrypted.Email != session.Email {
		t.Errorf("expected email %q, got %q", session.Email, decrypted.Email)
	}
	if len(decrypted.Groups) != 2 || decrypted.Groups[0] != "on-call" {
		t.Errorf("groups mismatch: got %v", decrypted.Groups)
	}
}

func TestSessionManager_ExpiredSession(t *testing.T) {
	cfg := &config.Config{
		CookieSecret: "my-very-secret-test-key-32-chars-long!",
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	session := &UserSession{
		Subject:   "expired@example.com",
		ExpiresAt: time.Now().Add(-1 * time.Minute), // in past
	}

	encrypted, err := sm.Encrypt(session)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	_, err = sm.Decrypt(encrypted)
	if err != ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestSessionManager_TamperedSession(t *testing.T) {
	cfg := &config.Config{
		CookieSecret: "my-very-secret-test-key-32-chars-long!",
	}

	sm, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("failed to create session manager: %v", err)
	}

	_, err = sm.Decrypt("invalid-base64-random-gibberish")
	if err != ErrInvalidSession {
		t.Errorf("expected ErrInvalidSession, got %v", err)
	}
}
