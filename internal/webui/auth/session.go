package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

var (
	ErrNoSession      = errors.New("no session cookie found")
	ErrInvalidSession = errors.New("invalid or tampered session cookie")
	ErrSessionExpired = errors.New("session has expired")
)

// UserSession holds the authenticated user details stored in the encrypted cookie.
type UserSession struct {
	Subject   string    `json:"sub"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Groups    []string  `json:"groups"`
	ExpiresAt time.Time `json:"exp"`
	IDToken   string    `json:"idToken,omitempty"`
}

// IsExpired checks if the session lifetime has elapsed.
func (s *UserSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// SessionManager manages encrypted session cookies.
type SessionManager struct {
	cfg       *config.Config
	cipherGCM cipher.AEAD
}

// NewSessionManager creates a new SessionManager using AES-GCM encryption.
func NewSessionManager(cfg *config.Config) (*SessionManager, error) {
	// Derive a 32-byte key from the configured secret
	hash := sha256.Sum256([]byte(cfg.CookieSecret))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &SessionManager{
		cfg:       cfg,
		cipherGCM: gcm,
	}, nil
}

// Encrypt serializes and encrypts the UserSession into a base64 string.
func (sm *SessionManager) Encrypt(session *UserSession) (string, error) {
	data, err := json.Marshal(session)
	if err != nil {
		return "", fmt.Errorf("marshal session: %w", err)
	}

	nonce := make([]byte, sm.cipherGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := sm.cipherGCM.Seal(nonce, nonce, data, nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt parses and decrypts a base64 cookie string into a UserSession.
func (sm *SessionManager) Decrypt(encryptedStr string) (*UserSession, error) {
	data, err := base64.RawURLEncoding.DecodeString(encryptedStr)
	if err != nil {
		return nil, ErrInvalidSession
	}

	nonceSize := sm.cipherGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidSession
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := sm.cipherGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrInvalidSession
	}

	var session UserSession
	if err := json.Unmarshal(plaintext, &session); err != nil {
		return nil, ErrInvalidSession
	}

	if session.IsExpired() {
		return nil, ErrSessionExpired
	}

	return &session, nil
}

// SetCookie writes the encrypted session cookie to the HTTP response.
func (sm *SessionManager) SetCookie(w http.ResponseWriter, session *UserSession) error {
	encrypted, err := sm.Encrypt(session)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     sm.cfg.CookieName,
		Value:    encrypted,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		Secure:   sm.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
	return nil
}

// ClearCookie removes the session cookie from the browser.
func (sm *SessionManager) ClearCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     sm.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   sm.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

// GetSession extracts and validates the UserSession from an HTTP request.
func (sm *SessionManager) GetSession(r *http.Request) (*UserSession, error) {
	cookie, err := r.Cookie(sm.cfg.CookieName)
	if err != nil {
		return nil, ErrNoSession
	}

	return sm.Decrypt(cookie.Value)
}
