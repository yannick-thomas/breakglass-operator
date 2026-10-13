package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/facade"
)

const origin = "http://localhost:8080"

type stubBackend struct {
	createErr  error
	lastActor  facade.Actor
	lastAccess facade.CreateAccessInput
}

func (s *stubBackend) ClientForToken(string) (client.Client, error) {
	return nil, errors.New("not used in dev mode")
}
func (s *stubBackend) DevClient() (client.Client, error) { return fake.NewFakeClient(), nil }
func (s *stubBackend) ListProfiles(context.Context, facade.Actor) ([]facade.ProfileDTO, error) {
	return []facade.ProfileDTO{}, nil
}
func (s *stubBackend) CreateAccess(_ context.Context, a facade.Actor, in facade.CreateAccessInput) (*facade.RequestDTO, error) {
	s.lastActor, s.lastAccess = a, in
	if s.createErr != nil {
		return nil, s.createErr
	}
	return &facade.RequestDTO{Kind: facade.AccessKindRequest, Name: "bgr-1"}, nil
}
func (s *stubBackend) ListMine(context.Context, string) ([]facade.RequestDTO, error) {
	return []facade.RequestDTO{}, nil
}
func (s *stubBackend) RevokeSession(context.Context, facade.Actor, string) error { return nil }
func (s *stubBackend) ListPendingApprovals(context.Context, facade.Actor) ([]facade.RequestDTO, error) {
	return []facade.RequestDTO{}, nil
}
func (s *stubBackend) CreateApproval(context.Context, facade.Actor, facade.CreateApprovalInput) error {
	return nil
}

func newTestHandler(t *testing.T, backend *stubBackend) *Handler {
	t.Helper()
	cfg := &config.Config{
		DevMode:    true,
		Port:       8080,
		PublicURL:  origin,
		CookieName: "breakglass_session",
		SessionTTL: time.Hour,
	}
	h := NewHandler(cfg, auth.NewStore(), nil, backend, fstest.MapFS{
		"index.html":       &fstest.MapFile{Data: []byte("<h1>BreakGlass</h1>")},
		"assets/main-1.js": &fstest.MapFile{Data: []byte("console.log(1)")},
	}, logr.Discard())
	h.whoami = func(context.Context, client.Client) (auth.Identity, error) {
		return auth.Identity{Username: "kubernetes-admin", Groups: []string{"system:masters"}}, nil
	}
	return h
}

// login performs the dev login and returns the session cookie.
func login(t *testing.T, h *Handler) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("expected login redirect, got %d: %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "breakglass_session" {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Errorf("session cookie must be HttpOnly and SameSite=Strict: %+v", c)
			}
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

func post(path, body string, cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func TestHandler_SecurityHeaders(t *testing.T) {
	h := newTestHandler(t, &stubBackend{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") ||
		!strings.Contains(csp, "script-src 'self';") || !strings.Contains(csp, "style-src 'self';") {
		t.Errorf("CSP must not allow inline scripts or styles: %q", csp)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("missing security headers: %v", w.Header())
	}
}

func TestHandler_StaticCaching(t *testing.T) {
	h := newTestHandler(t, &stubBackend{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("index must not be cached: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/main-1.js", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("hashed assets should be immutable: %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
}

func TestHandler_RequiresSession(t *testing.T) {
	h := newTestHandler(t, &stubBackend{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/me", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandler_DevLoginUsesKubernetesIdentity(t *testing.T) {
	h := newTestHandler(t, &stubBackend{})
	cookie := login(t, h)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.AddCookie(cookie)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	var me map[string]any
	if err := json.NewDecoder(w.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if me["username"] != "kubernetes-admin" || me["devMode"] != true {
		t.Errorf("unexpected identity: %v", me)
	}
}

func TestHandler_NoIdentitySwitchEndpoint(t *testing.T) {
	h := newTestHandler(t, &stubBackend{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/auth/dev-login?user=admin@example.com", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("expected the identity-switch endpoint to be gone, got %d", w.Code)
	}
}

func TestHandler_RejectsCrossSiteWrites(t *testing.T) {
	backend := &stubBackend{}
	h := newTestHandler(t, backend)
	cookie := login(t, h)
	body := `{"accessProfile":"observer","duration":"30m","reason":"INC-1"}`

	tests := map[string]struct {
		mutate func(*http.Request)
		want   int
	}{
		"missing origin":      {func(r *http.Request) { r.Header.Del("Origin") }, http.StatusForbidden},
		"foreign origin":      {func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.com") }, http.StatusForbidden},
		"cross-site fetch":    {func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		"form content type":   {func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, http.StatusUnsupportedMediaType},
		"same-origin request": {func(*http.Request) {}, http.StatusCreated},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := post("/api/v1/requests", body, cookie)
			tc.mutate(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Errorf("expected %d, got %d: %s", tc.want, w.Code, w.Body)
			}
		})
	}
	if backend.lastActor.Username != "kubernetes-admin" {
		t.Errorf("expected the write to run as the signed-in identity, got %q", backend.lastActor.Username)
	}
}

func TestHandler_RejectsUnknownFields(t *testing.T) {
	h := newTestHandler(t, &stubBackend{})
	cookie := login(t, h)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, post("/api/v1/requests", `{"accessProfile":"observer","duration":"30m","reason":"INC-1","requester":"someone"}`, cookie))
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown field, got %d", w.Code)
	}
}

func TestHandler_ErrorMapping(t *testing.T) {
	gr := schema.GroupResource{Group: "access.breakglass.io", Resource: "breakglassrequests"}
	tests := map[string]struct {
		err         error
		wantCode    int
		wantMessage string
	}{
		"admission denial": {
			err:         apierrors.NewForbidden(gr, "", errors.New(`admission webhook "vbreakglassrequest-v1alpha1.kb.io" denied the request: duration exceeds AccessProfile maximum`)),
			wantCode:    http.StatusForbidden,
			wantMessage: "duration exceeds AccessProfile maximum",
		},
		"webhook unavailable": {
			err:         apierrors.NewInternalError(errors.New(`Internal error occurred: failed calling webhook "vbreakglassrequest-v1alpha1.kb.io": connection refused`)),
			wantCode:    http.StatusServiceUnavailable,
			wantMessage: "Admission-Prüfung ist nicht erreichbar",
		},
		"invalid input": {
			err:         facade.ErrInvalidInput,
			wantCode:    http.StatusBadRequest,
			wantMessage: "invalid input",
		},
		"unexpected": {
			err:         errors.New("dial tcp 10.0.0.1:443: i/o timeout"),
			wantCode:    http.StatusBadGateway,
			wantMessage: "Kubernetes-API",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newTestHandler(t, &stubBackend{createErr: tc.err})
			cookie := login(t, h)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, post("/api/v1/requests", `{"accessProfile":"observer","duration":"30m","reason":"INC-1"}`, cookie))
			if w.Code != tc.wantCode || !strings.Contains(w.Body.String(), tc.wantMessage) {
				t.Errorf("expected %d containing %q, got %d: %s", tc.wantCode, tc.wantMessage, w.Code, w.Body)
			}
			if strings.Contains(w.Body.String(), "10.0.0.1") {
				t.Error("internal error details must not reach the browser")
			}
		})
	}
}

func TestHandler_UnauthorizedEndsSession(t *testing.T) {
	h := newTestHandler(t, &stubBackend{createErr: apierrors.NewUnauthorized("token expired")})
	cookie := login(t, h)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, post("/api/v1/requests", `{"accessProfile":"observer","duration":"30m","reason":"INC-1"}`, cookie))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected session to be ended, got %d", w.Code)
	}
}

func TestHandler_Logout(t *testing.T) {
	h := newTestHandler(t, &stubBackend{})
	cookie := login(t, h)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, post("/auth/logout", `{}`, cookie))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), loggedOutPath) {
		t.Fatalf("unexpected logout response %d: %s", w.Code, w.Body)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected session to be gone after logout, got %d", w.Code)
	}
}
