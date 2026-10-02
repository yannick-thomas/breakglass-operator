package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/facade"
)

type contextKey string

const userSessionContextKey contextKey = "user_session"

// Handler aggregates all routing and HTTP handlers for the WebUI.
type Handler struct {
	cfg        *config.Config
	sm         *auth.SessionManager
	oidc       *auth.OIDCClient
	facade     *facade.K8sFacade
	frontendFS fs.FS
	mux        *http.ServeMux
}

// NewHandler initializes routes and middlewares.
func NewHandler(cfg *config.Config, sm *auth.SessionManager, oidc *auth.OIDCClient, f *facade.K8sFacade, frontendFS fs.FS) *Handler {
	h := &Handler{
		cfg:        cfg,
		sm:         sm,
		oidc:       oidc,
		facade:     f,
		frontendFS: frontendFS,
		mux:        http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

// ServeHTTP implements http.Handler with global security headers.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Apply security headers
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")

	if h.cfg.CookieSecure {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	h.mux.ServeHTTP(w, r)
}

func (h *Handler) registerRoutes() {
	// Auth routes
	h.mux.HandleFunc("/auth/login", h.handleLogin)
	h.mux.HandleFunc("/auth/callback", h.handleCallback)
	h.mux.HandleFunc("/auth/logout", h.handleLogout)
	if h.cfg.DevMode {
		h.mux.HandleFunc("/auth/dev-login", h.handleDevLogin)
	}

	// API routes (Protected)
	h.mux.HandleFunc("/api/v1/me", h.requireAuth(h.handleMe))
	h.mux.HandleFunc("/api/v1/profiles", h.requireAuth(h.handleProfiles))
	h.mux.HandleFunc("/api/v1/requests", h.requireAuth(h.handleRequests))
	h.mux.HandleFunc("/api/v1/my-requests", h.requireAuth(h.handleMyRequests))
	h.mux.HandleFunc("/api/v1/requests/", h.requireAuth(h.handleRequestSubRoutes))
	h.mux.HandleFunc("/api/v1/approvals/pending", h.requireAuth(h.handlePendingApprovals))
	h.mux.HandleFunc("/api/v1/approvals", h.requireAuth(h.handleApprovals))

	// Health check
	h.mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Frontend Static Files
	if h.frontendFS != nil {
		fileServer := http.FileServer(http.FS(h.frontendFS))
		h.mux.Handle("/", fileServer)
	}
}

// requireAuth middleware ensures an authenticated UserSession is present.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := h.sm.GetSession(r)
		if err != nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				h.jsonError(w, "Unauthorized: authentication required", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), userSessionContextKey, session)
		next(w, r.WithContext(ctx))
	}
}

func getUserSession(r *http.Request) *auth.UserSession {
	if s, ok := r.Context().Value(userSessionContextKey).(*auth.UserSession); ok {
		return s
	}
	return nil
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if h.cfg.DevMode && !h.cfg.OIDCEnabled {
		// Dev mode auto-login
		session := &auth.UserSession{
			Subject:   h.cfg.DevDefaultUser,
			Email:     h.cfg.DevDefaultUser,
			Name:      "Dev Engineer",
			Groups:    strings.Split(h.cfg.DevDefaultGroups, ","),
			ExpiresAt: time.Now().Add(h.cfg.SessionTTL),
		}
		_ = h.sm.SetCookie(w, session)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	pkce, err := auth.GeneratePKCE()
	if err != nil {
		http.Error(w, "Failed to generate PKCE", http.StatusInternalServerError)
		return
	}

	state, err := auth.GenerateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store PKCE verifier and state in short-lived temporary cookie
	tempCookie := &http.Cookie{
		Name:     "bg_oidc_state",
		Value:    fmt.Sprintf("%s:%s", state, pkce.Verifier),
		Path:     "/auth/callback",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, tempCookie)

	authURL, err := h.oidc.GetAuthURL(state, pkce.Challenge)
	if err != nil {
		http.Error(w, "Failed to generate auth URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("bg_oidc_state")
	if err != nil {
		http.Error(w, "Missing OIDC state cookie", http.StatusBadRequest)
		return
	}

	parts := strings.Split(cookie.Value, ":")
	if len(parts) != 2 {
		http.Error(w, "Invalid OIDC state cookie", http.StatusBadRequest)
		return
	}
	expectedState, verifier := parts[0], parts[1]

	state := r.URL.Query().Get("state")
	if state == "" || state != expectedState {
		http.Error(w, "State mismatch or expired", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	session, err := h.oidc.ExchangeCode(r.Context(), code, verifier)
	if err != nil {
		http.Error(w, "Failed to exchange code: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if err := h.sm.SetCookie(w, session); err != nil {
		http.Error(w, "Failed to set session", http.StatusInternalServerError)
		return
	}

	// Clear temporary state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "bg_oidc_state",
		Value:    "",
		Path:     "/auth/callback",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	h.sm.ClearCookie(w)
	if r.Header.Get("Accept") == "application/json" {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.DevMode {
		http.Error(w, "Dev mode disabled", http.StatusForbidden)
		return
	}

	user := r.URL.Query().Get("user")
	if user == "" {
		user = h.cfg.DevDefaultUser
	}
	groups := r.URL.Query().Get("groups")
	if groups == "" {
		groups = h.cfg.DevDefaultGroups
	}

	session := &auth.UserSession{
		Subject:   user,
		Email:     user,
		Name:      strings.Split(user, "@")[0],
		Groups:    strings.Split(groups, ","),
		ExpiresAt: time.Now().Add(h.cfg.SessionTTL),
	}
	_ = h.sm.SetCookie(w, session)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleMe(w http.ResponseWriter, r *http.Request) {
	session := getUserSession(r)
	h.jsonResponse(w, session, http.StatusOK)
}

func (h *Handler) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	profiles, err := h.facade.ListProfiles(r.Context())
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, profiles, http.StatusOK)
}

func (h *Handler) handleRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input facade.CreateRequestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if input.AccessProfile == "" || input.Duration == "" || input.Reason == "" {
		h.jsonError(w, "Missing required fields: accessProfile, duration, reason", http.StatusBadRequest)
		return
	}

	user := getUserSession(r)
	created, err := h.facade.CreateRequest(r.Context(), user, input)
	if err != nil {
		if errors.Is(err, facade.ErrProfileNotFound) || errors.Is(err, facade.ErrInvalidDuration) {
			h.jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, created, http.StatusCreated)
}

func (h *Handler) handleMyRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getUserSession(r)
	requests, err := h.facade.ListMyRequests(r.Context(), user)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, requests, http.StatusOK)
}

func (h *Handler) handleRequestSubRoutes(w http.ResponseWriter, r *http.Request) {
	// URL pattern: /api/v1/requests/{name}/revoke
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/requests/")
	parts := strings.Split(path, "/")
	if len(parts) == 2 && parts[1] == "revoke" {
		h.handleRevokeRequest(w, r, parts[0])
		return
	}

	h.jsonError(w, "Not found", http.StatusNotFound)
}

func (h *Handler) handleRevokeRequest(w http.ResponseWriter, r *http.Request, reqName string) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getUserSession(r)
	if err := h.facade.RevokeRequest(r.Context(), user, reqName); err != nil {
		if errors.Is(err, facade.ErrForbidden) {
			h.jsonError(w, err.Error(), http.StatusForbidden)
			return
		}
		if errors.Is(err, facade.ErrRequestNotFound) || errors.Is(err, facade.ErrSessionNotFound) {
			h.jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, map[string]string{"status": "revoked", "request": reqName}, http.StatusOK)
}

func (h *Handler) handlePendingApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := getUserSession(r)
	approvals, err := h.facade.ListPendingApprovals(r.Context(), user)
	if err != nil {
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, approvals, http.StatusOK)
}

func (h *Handler) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var input facade.CreateApprovalInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.jsonError(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if input.RequestName == "" || input.Decision == "" {
		h.jsonError(w, "Missing required fields: requestName, decision", http.StatusBadRequest)
		return
	}

	user := getUserSession(r)
	if err := h.facade.CreateApproval(r.Context(), user, input); err != nil {
		if errors.Is(err, facade.ErrSelfApproval) || errors.Is(err, facade.ErrForbidden) {
			h.jsonError(w, err.Error(), http.StatusForbidden)
			return
		}
		if errors.Is(err, facade.ErrRequestNotFound) {
			h.jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		h.jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.jsonResponse(w, map[string]string{"status": "decision_recorded", "request": input.RequestName}, http.StatusCreated)
}

func (h *Handler) jsonResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, statusCode int) {
	h.jsonResponse(w, map[string]string{"error": message}, statusCode)
}
