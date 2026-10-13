package facade

import (
	"context"
	"errors"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

const (
	userJane = "oidc:jane@example.com"
	userMax  = "oidc:max@example.com"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := authorizationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// permissions maps "verb/profile" to the SelfSubjectAccessReview result.
type permissions map[string]bool

// newTestFacade returns a facade acting as userJane, whose reader and actor share one fake API
// server. The actor client answers SelfSubjectAccessReviews from perms, and
// the facade's reader is a client.Reader, so it cannot write at all.
func newTestFacade(t *testing.T, perms permissions, objs ...client.Object) (*K8sFacade, Actor, client.Client) {
	t.Helper()
	base := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()
	actorClient := interceptor.NewClient(base, interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.CreateOption) error {
			if review, ok := obj.(*authorizationv1.SelfSubjectAccessReview); ok {
				attrs := review.Spec.ResourceAttributes
				review.Status.Allowed = perms[attrs.Verb+"/"+attrs.Name]
				return nil
			}
			return c.Create(ctx, obj, opts...)
		},
	})
	return &K8sFacade{reader: base}, Actor{Username: userJane, Client: actorClient}, base
}

func profile(name string, mode v1alpha1.AccessDeliveryMode) *v1alpha1.AccessProfile {
	return &v1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid")},
		Spec: v1alpha1.AccessProfileSpec{
			TargetNamespace: "production",
			MaxDuration:     "1h",
			RoleRef:         v1alpha1.RoleReference{Kind: "ClusterRole", Name: "observer"},
			DeliveryMode:    mode,
		},
		Status: v1alpha1.AccessProfileStatus{
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}
}

func request(name, requester, profileName string, phase v1alpha1.RequestPhase) *v1alpha1.BreakGlassRequest {
	return &v1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name + "-uid")},
		Spec: v1alpha1.BreakGlassRequestSpec{
			AccessProfile: profileName,
			Requester:     v1alpha1.SubjectReference{Kind: v1alpha1.SubjectKindUser, Name: requester},
			Duration:      "30m",
			Reason:        "INC-1 investigate",
		},
		Status: v1alpha1.BreakGlassRequestStatus{Phase: phase},
	}
}

func session(name, subject string, requestRef *v1alpha1.BreakGlassRequestReference) *v1alpha1.BreakGlassSession {
	return &v1alpha1.BreakGlassSession{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.BreakGlassSessionSpec{
			AccessProfile: "observer",
			Subject:       v1alpha1.SubjectReference{Kind: v1alpha1.SubjectKindUser, Name: subject},
			Duration:      "30m",
			Reason:        "INC-1 investigate",
			RequestRef:    requestRef,
		},
		Status: v1alpha1.BreakGlassSessionStatus{Phase: v1alpha1.PhaseActive},
	}
}

func TestListProfiles_OnlyUsableProfiles(t *testing.T) {
	f, actor, _ := newTestFacade(t, permissions{"use/observer": true},
		profile("observer", v1alpha1.AccessDeliveryModeApprovalRequired),
		profile("secret-admin", v1alpha1.AccessDeliveryModeApprovalRequired),
	)

	profiles, err := f.ListProfiles(context.Background(), actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles[0].Name != "observer" || !profiles[0].IsReady {
		t.Fatalf("expected only the usable profile, got %+v", profiles)
	}
}

func TestListMine_PrivacyFiltering(t *testing.T) {
	own := request("bgr-own", userJane, "observer", v1alpha1.RequestPhaseSessionCreated)
	own.Status.SessionRef = &v1alpha1.BreakGlassObjectReference{Name: "bgs-from-request", UID: "s-uid"}

	f, _, _ := newTestFacade(t, nil,
		profile("observer", v1alpha1.AccessDeliveryModeApprovalRequired),
		own,
		request("bgr-other", userMax, "observer", v1alpha1.RequestPhasePending),
		// A prefix/suffix of the username must not match.
		request("bgr-lookalike", userJane+" ", "observer", v1alpha1.RequestPhasePending),
		session("bgs-from-request", userJane, &v1alpha1.BreakGlassRequestReference{Name: "bgr-own", UID: "bgr-own-uid"}),
		session("bgs-self-service", userJane, nil),
		session("bgs-other", userMax, nil),
	)

	mine, err := f.ListMine(context.Background(), userJane)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 2 {
		t.Fatalf("expected own request and own self-service session, got %+v", mine)
	}
	byName := map[string]RequestDTO{}
	for _, m := range mine {
		byName[m.Name] = m
	}
	req, ok := byName["bgr-own"]
	if !ok || req.Kind != AccessKindRequest || req.SessionName != "bgs-from-request" || !req.CanRevoke {
		t.Errorf("unexpected request entry: %+v", req)
	}
	if req.TargetNamespace != "production" {
		t.Errorf("expected namespace from profile, got %q", req.TargetNamespace)
	}
	if s, ok := byName["bgs-self-service"]; !ok || s.Kind != AccessKindSession || s.Phase != "Active" {
		t.Errorf("unexpected session entry: %+v", s)
	}
}

func TestListMine_IgnoresSessionNotRecordedOnRequest(t *testing.T) {
	// The request has no SessionRef: a session pointing at it is not attributed.
	f, _, _ := newTestFacade(t, nil,
		request("bgr-own", userJane, "observer", v1alpha1.RequestPhasePending),
		session("bgs-unrelated", userJane, &v1alpha1.BreakGlassRequestReference{Name: "bgr-own", UID: "bgr-own-uid"}),
	)

	mine, err := f.ListMine(context.Background(), userJane)
	if err != nil {
		t.Fatal(err)
	}
	if len(mine) != 1 || mine[0].SessionName != "" || mine[0].CanRevoke {
		t.Fatalf("expected request without attached session, got %+v", mine)
	}
}

func TestListPendingApprovals_Filtering(t *testing.T) {
	expired := request("bgr-expired", userMax, "observer", v1alpha1.RequestPhasePending)
	expired.Status.ExpiresAt = &metav1.Time{Time: time.Now().Add(-time.Minute)}

	f, actor, _ := newTestFacade(t, permissions{"approve/observer": true},
		request("bgr-open", userMax, "observer", v1alpha1.RequestPhasePending),
		request("bgr-own", userJane, "observer", v1alpha1.RequestPhasePending),
		request("bgr-decided", userMax, "observer", v1alpha1.RequestPhaseApproved),
		request("bgr-other-profile", userMax, "db-admin", v1alpha1.RequestPhasePending),
		expired,
	)

	pending, err := f.ListPendingApprovals(context.Background(), actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Name != "bgr-open" || !pending[0].CanApprove {
		t.Fatalf("expected only the open, approvable request of another person, got %+v", pending)
	}
}

func TestCreateApproval(t *testing.T) {
	tests := map[string]struct {
		request  *v1alpha1.BreakGlassRequest
		decision string
		wantErr  error
	}{
		"approve": {request("bgr-1", userMax, "observer", v1alpha1.RequestPhasePending), "Approved", nil},
		"deny":    {request("bgr-1", userMax, "observer", v1alpha1.RequestPhasePending), "Denied", nil},
		// Anything but the exact decision must not default to approval.
		"unknown decision": {request("bgr-1", userMax, "observer", v1alpha1.RequestPhasePending), "yes", ErrInvalidInput},
		"self approval":    {request("bgr-1", userJane, "observer", v1alpha1.RequestPhasePending), "Approved", ErrSelfApproval},
		"not pending":      {request("bgr-1", userMax, "observer", v1alpha1.RequestPhaseDenied), "Approved", ErrNotPending},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f, actor, store := newTestFacade(t, nil, tc.request)

			err := f.CreateApproval(context.Background(), actor, CreateApprovalInput{
				RequestName: "bgr-1", Decision: tc.decision, Comment: "  ok  ",
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}

			var approval v1alpha1.BreakGlassApproval
			getErr := store.Get(context.Background(), types.NamespacedName{Name: v1alpha1.ApprovalNameForRequestUID("bgr-1-uid")}, &approval)
			if tc.wantErr != nil {
				if getErr == nil {
					t.Fatal("expected no approval to be written")
				}
				return
			}
			if getErr != nil {
				t.Fatalf("expected approval to be written: %v", getErr)
			}
			if string(approval.Spec.Decision) != tc.decision || approval.Spec.RequestRef.UID != "bgr-1-uid" ||
				approval.Spec.Approver.Name != userJane || approval.Spec.Comment != "ok" {
				t.Errorf("unexpected approval: %+v", approval.Spec)
			}
		})
	}
}

func TestCreateAccess_RoutesByDeliveryMode(t *testing.T) {
	f, actor, store := newTestFacade(t, nil,
		profile("observer", v1alpha1.AccessDeliveryModeApprovalRequired),
		profile("self-observer", v1alpha1.AccessDeliveryModeSelfService),
	)
	ctx := context.Background()

	created, err := f.CreateAccess(ctx, actor, CreateAccessInput{AccessProfile: "observer", Duration: "30m", Reason: " INC-1 "})
	if err != nil {
		t.Fatal(err)
	}
	if created.Kind != AccessKindRequest {
		t.Errorf("expected a BreakGlassRequest, got %+v", created)
	}
	var reqs v1alpha1.BreakGlassRequestList
	if err := store.List(ctx, &reqs); err != nil || len(reqs.Items) != 1 || reqs.Items[0].Spec.Reason != "INC-1" {
		t.Fatalf("expected one written request, got %+v, %v", reqs.Items, err)
	}

	created, err = f.CreateAccess(ctx, actor, CreateAccessInput{AccessProfile: "self-observer", Duration: "30m", Reason: "INC-1"})
	if err != nil {
		t.Fatal(err)
	}
	if created.Kind != AccessKindSession {
		t.Errorf("expected a BreakGlassSession, got %+v", created)
	}
}

func TestCreateAccess_RejectsInvalidInput(t *testing.T) {
	f, actor, _ := newTestFacade(t, nil, profile("observer", v1alpha1.AccessDeliveryModeApprovalRequired))

	for _, input := range []CreateAccessInput{
		{AccessProfile: "observer", Duration: "30m", Reason: "   "},
		{AccessProfile: "observer", Duration: "-5m", Reason: "INC-1"},
		{AccessProfile: "observer", Duration: "soon", Reason: "INC-1"},
	} {
		if _, err := f.CreateAccess(context.Background(), actor, input); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("expected ErrInvalidInput for %+v, got %v", input, err)
		}
	}
	if _, err := f.CreateAccess(context.Background(), actor, CreateAccessInput{AccessProfile: "missing", Duration: "30m", Reason: "INC-1"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRevokeSession(t *testing.T) {
	ended := session("bgs-ended", userJane, nil)
	ended.Status.Phase = v1alpha1.PhaseExpired

	f, actor, store := newTestFacade(t, nil,
		session("bgs-own", userJane, nil),
		session("bgs-other", userMax, nil),
		ended,
	)
	ctx := context.Background()

	if err := f.RevokeSession(ctx, actor, "bgs-other"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected another person's session to be reported as not found, got %v", err)
	}
	if err := f.RevokeSession(ctx, actor, "bgs-ended"); !errors.Is(err, ErrNotRevocable) {
		t.Errorf("expected ErrNotRevocable, got %v", err)
	}
	if err := f.RevokeSession(ctx, actor, "bgs-own"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}

	var got v1alpha1.BreakGlassSession
	if err := store.Get(ctx, types.NamespacedName{Name: "bgs-own"}, &got); err != nil || !got.Spec.Revoked {
		t.Errorf("expected own session to be revoked, got %+v, %v", got.Spec, err)
	}
	if err := store.Get(ctx, types.NamespacedName{Name: "bgs-other"}, &got); err != nil || got.Spec.Revoked {
		t.Errorf("expected other session to be untouched, got %+v, %v", got.Spec, err)
	}
}
