package facade

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

func setupTestScheme() *runtime.Scheme {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)
	return scheme
}

func TestK8sFacade_ListProfiles(t *testing.T) {
	scheme := setupTestScheme()
	profile := &v1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "prod-db-observer",
			Annotations: map[string]string{
				"description": "Read access to production databases",
			},
		},
		Spec: v1alpha1.AccessProfileSpec{
			TargetNamespace: "production",
			MaxDuration:     "1h",
			RoleRef: v1alpha1.RoleReference{
				Kind: "ClusterRole",
				Name: "db-observer",
			},
			DeliveryMode: v1alpha1.AccessDeliveryModeApprovalRequired,
		},
		Status: v1alpha1.AccessProfileStatus{
			Conditions: []metav1.Condition{
				{
					Type:   "Ready",
					Status: metav1.ConditionTrue,
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(profile).Build()
	facade := &K8sFacade{client: fakeClient, cfg: &config.Config{}}

	profiles, err := facade.ListProfiles(context.Background())
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}

	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].Name != "prod-db-observer" || profiles[0].TargetNamespace != "production" {
		t.Errorf("unexpected profile data: %+v", profiles[0])
	}
	if !profiles[0].IsReady {
		t.Errorf("expected profile to be Ready")
	}
}

func TestK8sFacade_ListMyRequests_PrivacyFiltering(t *testing.T) {
	scheme := setupTestScheme()

	reqUserA := &v1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bgr-user-a",
		},
		Spec: v1alpha1.BreakGlassRequestSpec{
			AccessProfile:    "prod-observer",
			AccessProfileUID: "uid-123",
			Requester: v1alpha1.SubjectReference{
				Kind: v1alpha1.SubjectKindUser,
				Name: "alice@example.com",
			},
			Duration:   "30m",
			RequestTTL: "15m",
			Reason:     "INC-100: Alice reason",
		},
	}

	reqUserB := &v1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bgr-user-b",
		},
		Spec: v1alpha1.BreakGlassRequestSpec{
			AccessProfile:    "prod-observer",
			AccessProfileUID: "uid-123",
			Requester: v1alpha1.SubjectReference{
				Kind: v1alpha1.SubjectKindUser,
				Name: "bob@example.com",
			},
			Duration:   "30m",
			RequestTTL: "15m",
			Reason:     "INC-200: Bob sensitive reason",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(reqUserA, reqUserB).Build()
	facade := &K8sFacade{client: fakeClient, cfg: &config.Config{}}

	userA := &auth.UserSession{
		Subject: "alice@example.com",
		Email:   "alice@example.com",
	}

	// Alice requests her view
	aliceRequests, err := facade.ListMyRequests(context.Background(), userA)
	if err != nil {
		t.Fatalf("ListMyRequests failed: %v", err)
	}

	// Alice should ONLY see her own request, NEVER Bob's request
	if len(aliceRequests) != 1 {
		t.Fatalf("expected exactly 1 request for Alice, got %d", len(aliceRequests))
	}
	if aliceRequests[0].Name != "bgr-user-a" {
		t.Errorf("expected request 'bgr-user-a', got %s", aliceRequests[0].Name)
	}
	if aliceRequests[0].Reason != "INC-100: Alice reason" {
		t.Errorf("unexpected reason: %s", aliceRequests[0].Reason)
	}
}

func TestK8sFacade_AntiSelfApproval(t *testing.T) {
	scheme := setupTestScheme()

	req := &v1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "bgr-pending-1",
			UID:  "req-uid-999",
		},
		Spec: v1alpha1.BreakGlassRequestSpec{
			AccessProfile:    "prod-observer",
			AccessProfileUID: "uid-123",
			Requester: v1alpha1.SubjectReference{
				Kind: v1alpha1.SubjectKindUser,
				Name: "requester@example.com",
			},
			Duration:   "30m",
			RequestTTL: "15m",
			Reason:     "Fix prod",
		},
		Status: v1alpha1.BreakGlassRequestStatus{
			Phase: v1alpha1.RequestPhasePending,
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(req).Build()
	facade := &K8sFacade{client: fakeClient, cfg: &config.Config{}}

	requesterUser := &auth.UserSession{
		Subject: "requester@example.com",
		Email:   "requester@example.com",
	}

	approverUser := &auth.UserSession{
		Subject: "approver@example.com",
		Email:   "approver@example.com",
	}

	// 1. Pending Approvals list should NOT include requester's own request for requester
	pendingForRequester, _ := facade.ListPendingApprovals(context.Background(), requesterUser)
	if len(pendingForRequester) != 0 {
		t.Errorf("expected 0 pending approvals for requester, got %d", len(pendingForRequester))
	}

	// 2. Approver SHOULD see the pending request
	pendingForApprover, _ := facade.ListPendingApprovals(context.Background(), approverUser)
	if len(pendingForApprover) != 1 {
		t.Errorf("expected 1 pending approval for approver, got %d", len(pendingForApprover))
	}

	// 3. Self-approval attempt must fail
	selfApproveErr := facade.CreateApproval(context.Background(), requesterUser, CreateApprovalInput{
		RequestName: "bgr-pending-1",
		Decision:    "Approved",
	})
	if selfApproveErr != ErrSelfApproval {
		t.Errorf("expected ErrSelfApproval, got %v", selfApproveErr)
	}

	// 4. Legitimate approver approval succeeds
	err := facade.CreateApproval(context.Background(), approverUser, CreateApprovalInput{
		RequestName: "bgr-pending-1",
		Decision:    "Approved",
		Comment:     "Verified ticket INC-123",
	})
	if err != nil {
		t.Fatalf("approver approval failed: %v", err)
	}
}

func TestK8sFacade_CreateRequest_DurationLimit(t *testing.T) {
	scheme := setupTestScheme()
	profile := &v1alpha1.AccessProfile{
		ObjectMeta: metav1.ObjectMeta{
			Name: "short-profile",
			UID:  "prof-uid-1",
		},
		Spec: v1alpha1.AccessProfileSpec{
			TargetNamespace: "test-ns",
			MaxDuration:     "30m",
		},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(profile).Build()
	facade := &K8sFacade{client: fakeClient, cfg: &config.Config{}}

	user := &auth.UserSession{Subject: "test@example.com"}

	// Request duration exceeding max duration
	_, err := facade.CreateRequest(context.Background(), user, CreateRequestInput{
		AccessProfile: "short-profile",
		Duration:      "2h",
		Reason:        "Need long access",
	})

	if err == nil {
		t.Fatal("expected error for excessive duration, got nil")
	}
}
