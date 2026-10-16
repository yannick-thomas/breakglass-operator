package handler

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"strings"

	"github.com/go-logr/logr"
	"golang.org/x/oauth2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/facade"
)

const (
	maxBodyBytes    = 16 << 10
	stateCookieName = "breakglass_oidc_state"
	loggedOutPath   = "/logged-out.html"

	outcomeDenied      = "denied"
	outcomeInvalid     = "invalid"
	outcomeUnavailable = "unavailable"
	outcomeError       = "error"

	// The Vite build emits only external scripts and stylesheets, so neither
	// inline scripts nor inline styles are allowed.
	contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; " +
		"img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; " +
		"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)

// Backend is the Kubernetes facade used by the handler.
type Backend interface {
	ClientForToken(token string) (client.Client, error)
	DevClient() (client.Client, error)
	ListProfiles(ctx context.Context, actor facade.Actor) ([]facade.ProfileDTO, error)
	CreateAccess(ctx context.Context, actor facade.Actor, input facade.CreateAccessInput) (*facade.RequestDTO, error)
	ListMine(ctx context.Context, username string) ([]facade.RequestDTO, error)
	RevokeSession(ctx context.Context, actor facade.Actor, namespace, sessionName string) error
	ListPendingApprovals(ctx context.Context, actor facade.Actor) ([]facade.RequestDTO, error)
	CreateApproval(ctx context.Context, actor facade.Actor, input facade.CreateApprovalInput) error
}

// Handler aggregates all routing and HTTP handlers for the WebUI.
type Handler struct {
	cfg            *config.Config
	store          *auth.Store
	oidc           *auth.OIDCClient // nil in dev mode
	backend        Backend
	whoami         func(context.Context, client.Client) (auth.Identity, error)
	frontendFS     fs.FS
	log            logr.Logger
	allowedOrigins map[string]struct{}
	mux            *http.ServeMux
}

// NewHandler initializes routes and middlewares.
func NewHandler(cfg *config.Config, store *auth.Store, oidc *auth.OIDCClient, backend Backend, frontendFS fs.FS, log logr.Logger) *Handler {
	h := &Handler{
		cfg:            cfg,
		store:          store,
		oidc:           oidc,
		backend:        backend,
		whoami:         facade.Whoami,
		frontendFS:     frontendFS,
		log:            log,
		allowedOrigins: map[string]struct{}{strings.TrimSuffix(cfg.PublicURL, "/"): {}},
		mux:            http.NewServeMux(),
	}
	if cfg.DevMode {
		h.allowedOrigins[fmt.Sprintf("http://localhost:%d", cfg.Port)] = struct{}{}
		h.allowedOrigins[fmt.Sprintf("http://127.0.0.1:%d", cfg.Port)] = struct{}{}
	}
	h.registerRoutes()
	return h
}

// ServeHTTP implements http.Handler with global security headers.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	if h.cfg.CookieSecure {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	h.mux.ServeHTTP(w, r)
}

func (h *Handler) registerRoutes() {
	h.mux.HandleFunc("GET /auth/login", h.handleLogin)
	h.mux.HandleFunc("GET /auth/callback", h.handleCallback)
	h.mux.HandleFunc("POST /auth/logout", h.sameOrigin(h.handleLogout))

	h.mux.HandleFunc("GET /api/v1/me", h.withActor(h.handleMe))
	h.mux.HandleFunc("GET /api/v1/profiles", h.withActor(h.handleProfiles))
	h.mux.HandleFunc("POST /api/v1/requests", h.sameOrigin(h.withActor(h.handleCreateAccess)))
	h.mux.HandleFunc("GET /api/v1/my-requests", h.withActor(h.handleMyRequests))
	h.mux.HandleFunc("POST /api/v1/namespaces/{namespace}/sessions/{name}/revoke", h.sameOrigin(h.withActor(h.handleRevoke)))
	h.mux.HandleFunc("GET /api/v1/approvals/pending", h.withActor(h.handlePendingApprovals))
	h.mux.HandleFunc("POST /api/v1/approvals", h.sameOrigin(h.withActor(h.handleCreateApproval)))

	h.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	if h.frontendFS != nil {
		files := http.FileServer(http.FS(h.frontendFS))
		h.mux.Handle("GET /", files)
		// Vite puts a content hash into every asset name, so assets can be
		// cached forever; index.html stays no-store and picks up new hashes.
		h.mux.Handle("GET /assets/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			files.ServeHTTP(w, r)
		}))
	}
}

type actorHandler func(w http.ResponseWriter, r *http.Request, sess *auth.Session, actor facade.Actor)

// withActor resolves the session and builds a Kubernetes client that carries
// the person's own credential. There is no fallback to another identity.
func (h *Handler) withActor(next actorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.session(r)
		if err != nil {
			h.unauthorized(w)
			return
		}

		var c client.Client
		if h.cfg.DevMode {
			c, err = h.backend.DevClient()
		} else {
			var token string
			token, err = h.oidc.BearerToken(r.Context(), sess)
			if err == nil {
				c, err = h.backend.ClientForToken(token)
			}
		}
		if err != nil {
			if errors.Is(err, auth.ErrSessionExpired) {
				h.endSession(w, sess)
				h.unauthorized(w)
				return
			}
			h.log.Error(err, "Failed to build user Kubernetes client")
			h.jsonError(w, "Die Anmeldung konnte nicht an Kubernetes weitergegeben werden.", http.StatusInternalServerError)
			return
		}

		next(w, r, sess, facade.Actor{Username: sess.Identity.Username, Client: c})
	}
}

// sameOrigin rejects cross-site state-changing requests. Together with the
// SameSite=Strict session cookie and the required JSON content type this
// protects every POST endpoint against CSRF.
func (h *Handler) sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			h.jsonError(w, "Cross-Site-Anfragen sind nicht erlaubt.", http.StatusForbidden)
			return
		}
		if _, ok := h.allowedOrigins[r.Header.Get("Origin")]; !ok {
			h.jsonError(w, "Ungültiger Origin.", http.StatusForbidden)
			return
		}
		if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
			h.jsonError(w, "Content-Type application/json erforderlich.", http.StatusUnsupportedMediaType)
			return
		}
		next(w, r)
	}
}

func (h *Handler) session(r *http.Request) (*auth.Session, error) {
	cookie, err := r.Cookie(h.cfg.CookieName)
	if err != nil {
		return nil, auth.ErrSessionExpired
	}
	return h.store.Get(cookie.Value)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if h.cfg.DevMode {
		h.devLogin(w, r)
		return
	}

	state, err1 := auth.RandomString(32)
	nonce, err2 := auth.RandomString(32)
	if err := errors.Join(err1, err2); err != nil {
		h.log.Error(err, "Failed to generate login parameters")
		http.Error(w, "Anmeldung konnte nicht gestartet werden.", http.StatusInternalServerError)
		return
	}
	pending := auth.PendingLogin{Nonce: nonce, PKCEVerifier: oauth2.GenerateVerifier()}
	if err := h.store.AddPending(state, pending); err != nil {
		h.log.Error(err, "Failed to store pending login")
		http.Error(w, "Zu viele gleichzeitige Anmeldungen. Bitte später erneut versuchen.", http.StatusServiceUnavailable)
		return
	}

	// Lax is required: the IdP redirects back with a cross-site navigation.
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/auth/callback",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, h.oidc.AuthCodeURL(state, pending), http.StatusFound)
}

func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	if h.cfg.DevMode {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: stateCookieName, Path: "/auth/callback", MaxAge: -1,
		HttpOnly: true, Secure: h.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})

	q := r.URL.Query()
	if q.Get("error") != "" {
		h.log.Info("OIDC provider returned an error", "error", q.Get("error"))
		http.Error(w, "Die Anmeldung wurde vom Identity Provider abgelehnt.", http.StatusUnauthorized)
		return
	}
	cookie, err := r.Cookie(stateCookieName)
	state := q.Get("state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		http.Error(w, "Ungültiger oder abgelaufener Anmeldevorgang.", http.StatusBadRequest)
		return
	}
	pending, ok := h.store.TakePending(state)
	if !ok || q.Get("code") == "" {
		http.Error(w, "Ungültiger oder abgelaufener Anmeldevorgang.", http.StatusBadRequest)
		return
	}

	tokens, err := h.oidc.Exchange(r.Context(), q.Get("code"), pending)
	if err != nil {
		h.log.Error(err, "Failed to complete OIDC login")
		http.Error(w, "Die Anmeldung konnte nicht verifiziert werden.", http.StatusUnauthorized)
		return
	}
	c, err := h.backend.ClientForToken(tokens.IDToken)
	if err != nil {
		h.log.Error(err, "Failed to build user Kubernetes client")
		http.Error(w, "Die Anmeldung konnte nicht verarbeitet werden.", http.StatusInternalServerError)
		return
	}
	h.startSession(w, r, c, tokens.DisplayName, tokens)
}

// devLogin signs the developer in with their kubeconfig identity. There is
// deliberately no way to choose an identity: switching persona means
// switching kubeconfig context and restarting the WebUI.
func (h *Handler) devLogin(w http.ResponseWriter, r *http.Request) {
	c, err := h.backend.DevClient()
	if err != nil {
		h.log.Error(err, "Failed to load dev Kubernetes client")
		http.Error(w, "Dev-Modus ist nicht verfügbar.", http.StatusInternalServerError)
		return
	}
	h.startSession(w, r, c, "", nil)
}

// startSession resolves the Kubernetes identity of the credential. If the API
// server does not accept the credential, the person cannot use the WebUI:
// the UI never substitutes another identity.
func (h *Handler) startSession(w http.ResponseWriter, r *http.Request, c client.Client, displayName string, tokens *auth.TokenSet) {
	identity, err := h.whoami(r.Context(), c)
	if err != nil {
		if apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err) {
			h.log.Error(err, "Kubernetes did not accept the login credential")
			http.Error(w, "Kubernetes akzeptiert diese Anmeldung nicht. Bitte wende dich an das Plattform-Team.", http.StatusForbidden)
			return
		}
		h.log.Error(err, "Could not resolve Kubernetes identity")
		http.Error(w, "Die Kubernetes-API ist nicht erreichbar. Bitte später erneut versuchen.", http.StatusBadGateway)
		return
	}
	if displayName == "" {
		displayName = identity.Username
	}

	sess := auth.NewSession(identity, displayName, tokens, h.cfg.SessionTTL)
	if err := h.store.Add(sess); err != nil {
		h.log.Error(err, "Failed to store session")
		http.Error(w, "Die Sitzung konnte nicht angelegt werden.", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.CookieName,
		Value:    sess.ID,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   h.cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
	h.log.Info("Signed in WebUI user")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	redirect := loggedOutPath
	if sess, err := h.session(r); err == nil {
		if h.oidc != nil {
			if u := h.oidc.LogoutURL(sess, strings.TrimSuffix(h.cfg.PublicURL, "/")+loggedOutPath); u != "" {
				redirect = u
			}
		}
		h.endSession(w, sess)
		h.log.Info("Signed out WebUI user")
	}
	h.jsonResponse(w, map[string]string{"redirect": redirect}, http.StatusOK)
}

func (h *Handler) endSession(w http.ResponseWriter, sess *auth.Session) {
	h.store.Delete(sess.ID)
	http.SetCookie(w, &http.Cookie{
		Name: h.cfg.CookieName, Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: h.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) handleMe(w http.ResponseWriter, _ *http.Request, sess *auth.Session, _ facade.Actor) {
	h.jsonResponse(w, map[string]any{
		"username":    sess.Identity.Username,
		"displayName": sess.DisplayName,
		"groups":      sess.Identity.Groups,
		"devMode":     h.cfg.DevMode,
	}, http.StatusOK)
}

func (h *Handler) handleProfiles(w http.ResponseWriter, r *http.Request, sess *auth.Session, actor facade.Actor) {
	profiles, err := h.backend.ListProfiles(r.Context(), actor)
	if err != nil {
		h.writeError(w, sess, "list-profiles", err)
		return
	}
	h.jsonResponse(w, profiles, http.StatusOK)
}

func (h *Handler) handleCreateAccess(w http.ResponseWriter, r *http.Request, sess *auth.Session, actor facade.Actor) {
	var input facade.CreateAccessInput
	if !h.decode(w, r, &input) {
		return
	}
	created, err := h.backend.CreateAccess(r.Context(), actor, input)
	if err != nil {
		h.writeError(w, sess, "create-access", err)
		return
	}
	h.log.Info("Recorded WebUI action", "action", "create-access", "outcome", "success", "kind", created.Kind, "namespace", created.Namespace, "ref", created.Name)
	h.jsonResponse(w, created, http.StatusCreated)
}

func (h *Handler) handleMyRequests(w http.ResponseWriter, r *http.Request, sess *auth.Session, actor facade.Actor) {
	requests, err := h.backend.ListMine(r.Context(), actor.Username)
	if err != nil {
		h.writeError(w, sess, "list-mine", err)
		return
	}
	h.jsonResponse(w, requests, http.StatusOK)
}

func (h *Handler) handleRevoke(w http.ResponseWriter, r *http.Request, sess *auth.Session, actor facade.Actor) {
	namespace, name := r.PathValue("namespace"), r.PathValue("name")
	if err := h.backend.RevokeSession(r.Context(), actor, namespace, name); err != nil {
		h.writeError(w, sess, "revoke-session", err)
		return
	}
	h.log.Info("Recorded WebUI action", "action", "revoke-session", "outcome", "success", "namespace", namespace, "ref", name)
	h.jsonResponse(w, map[string]string{"status": "revoked", "namespace": namespace, "session": name}, http.StatusOK)
}

func (h *Handler) handlePendingApprovals(w http.ResponseWriter, r *http.Request, sess *auth.Session, actor facade.Actor) {
	approvals, err := h.backend.ListPendingApprovals(r.Context(), actor)
	if err != nil {
		h.writeError(w, sess, "list-approvals", err)
		return
	}
	h.jsonResponse(w, approvals, http.StatusOK)
}

func (h *Handler) handleCreateApproval(w http.ResponseWriter, r *http.Request, sess *auth.Session, actor facade.Actor) {
	var input facade.CreateApprovalInput
	if !h.decode(w, r, &input) {
		return
	}
	if err := h.backend.CreateApproval(r.Context(), actor, input); err != nil {
		h.writeError(w, sess, "create-approval", err)
		return
	}
	h.log.Info("Recorded WebUI action", "action", "create-approval", "outcome", "success", "namespace", input.Namespace, "ref", input.RequestName)
	h.jsonResponse(w, map[string]string{"status": "decision_recorded", "namespace": input.Namespace, "request": input.RequestName}, http.StatusCreated)
}

func (h *Handler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		h.jsonError(w, "Ungültiger Request-Body.", http.StatusBadRequest)
		return false
	}
	return true
}

// writeError maps facade and Kubernetes errors to responses. Admission and
// RBAC messages are passed through: they are written for requesters and
// describe their own request. Everything else is logged and generalized.
// Logs carry only the action and outcome family, never names or reasons.
func (h *Handler) writeError(w http.ResponseWriter, sess *auth.Session, action string, err error) {
	status, message := http.StatusBadGateway, "Die Kubernetes-API hat die Anfrage nicht verarbeitet."
	outcome := outcomeDenied

	switch {
	case errors.Is(err, facade.ErrInvalidInput):
		status, message, outcome = http.StatusBadRequest, err.Error(), outcomeInvalid
	case errors.Is(err, facade.ErrNotFound):
		status, message = http.StatusNotFound, "Nicht gefunden."
	case errors.Is(err, facade.ErrSelfApproval):
		status, message = http.StatusForbidden, "Eigene Anträge können nicht selbst entschieden werden."
	case errors.Is(err, facade.ErrNotPending):
		status, message = http.StatusConflict, "Der Antrag ist nicht mehr offen."
	case errors.Is(err, facade.ErrNotRevocable):
		status, message = http.StatusConflict, "Die Session ist bereits beendet."
	case apierrors.IsUnauthorized(err):
		h.endSession(w, sess)
		status, message = http.StatusUnauthorized, "Die Anmeldung ist abgelaufen."
	case apierrors.IsAlreadyExists(err):
		status, message = http.StatusConflict, "Für diesen Antrag wurde bereits entschieden."
	case apierrors.IsConflict(err):
		status, message = http.StatusConflict, "Das Objekt wurde zwischenzeitlich geändert. Bitte neu laden."
	case apierrors.IsForbidden(err), apierrors.IsInvalid(err), apierrors.IsBadRequest(err):
		status, message = statusCode(err), apiMessage(err)
	case apierrors.IsInternalError(err) && strings.Contains(err.Error(), "failed calling webhook"):
		status = http.StatusServiceUnavailable
		message = "Neue Zugriffe können aus Sicherheitsgründen derzeit nicht angefordert werden: die Admission-Prüfung ist nicht erreichbar."
		outcome = outcomeUnavailable
	default:
		outcome = outcomeError
		h.log.Error(err, "WebUI action failed", "action", action)
	}

	if outcome != outcomeError {
		h.log.Info("Recorded WebUI action", "action", action, "outcome", outcome)
	}
	if status == http.StatusUnauthorized {
		h.unauthorized(w)
		return
	}
	h.jsonError(w, message, status)
}

func statusCode(err error) int {
	var status apierrors.APIStatus
	if errors.As(err, &status) && status.Status().Code != 0 {
		return int(status.Status().Code)
	}
	return http.StatusBadRequest
}

func apiMessage(err error) string {
	var status apierrors.APIStatus
	if !errors.As(err, &status) {
		return "Die Anfrage wurde abgelehnt."
	}
	msg := status.Status().Message
	if _, after, ok := strings.Cut(msg, "denied the request: "); ok {
		return after
	}
	return msg
}

func (h *Handler) unauthorized(w http.ResponseWriter) {
	h.jsonError(w, "Anmeldung erforderlich.", http.StatusUnauthorized)
}

func (h *Handler) jsonResponse(w http.ResponseWriter, data any, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) jsonError(w http.ResponseWriter, message string, statusCode int) {
	h.jsonResponse(w, map[string]string{"error": message}, statusCode)
}
