package facade

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

var (
	ErrForbidden       = errors.New("forbidden: action not allowed for current user")
	ErrSelfApproval    = errors.New("forbidden: requester cannot approve own request")
	ErrProfileNotFound = errors.New("access profile not found")
	ErrRequestNotFound = errors.New("breakglass request not found")
	ErrInvalidDuration = errors.New("requested duration exceeds profile limit")
	ErrSessionNotFound = errors.New("associated breakglass session not found")
)

// ProfileDTO is a safe, capability-oriented view of an AccessProfile.
type ProfileDTO struct {
	Name            string `json:"name"`
	TargetNamespace string `json:"targetNamespace"`
	MaxDuration     string `json:"maxDuration"`
	DeliveryMode    string `json:"deliveryMode"`
	RoleRef         string `json:"roleRef"`
	Description     string `json:"description"`
	IsReady         bool   `json:"isReady"`
}

// RequestDTO is a privacy-filtered view of a BreakGlassRequest and its session state.
type RequestDTO struct {
	Name             string     `json:"name"`
	UID              string     `json:"uid"`
	AccessProfile    string     `json:"accessProfile"`
	TargetNamespace  string     `json:"targetNamespace"`
	Requester        string     `json:"requester"`
	Duration         string     `json:"duration"`
	Reason           string     `json:"reason"`
	Phase            string     `json:"phase"`
	CreatedAt        time.Time  `json:"createdAt"`
	ExpiresAt        *time.Time `json:"expiresAt,omitempty"`
	SessionName      string     `json:"sessionName,omitempty"`
	SessionPhase     string     `json:"sessionPhase,omitempty"`
	SessionExpiresAt *time.Time `json:"sessionExpiresAt,omitempty"`
	ApprovalDecision string     `json:"approvalDecision,omitempty"`
	Approver         string     `json:"approver,omitempty"`
	CanRevoke        bool       `json:"canRevoke"`
	CanApprove       bool       `json:"canApprove"`
}

// CreateRequestInput defines user input for requesting access.
type CreateRequestInput struct {
	AccessProfile string `json:"accessProfile"`
	Duration      string `json:"duration"`
	Reason        string `json:"reason"`
}

// CreateApprovalInput defines approver input for approving or denying a request.
type CreateApprovalInput struct {
	RequestName string `json:"requestName"`
	Decision    string `json:"decision"` // "Approved" or "Denied"
	Comment     string `json:"comment,omitempty"`
}

// K8sFacade mediates interactions between the WebUI BFF and the Kubernetes API.
type K8sFacade struct {
	client client.Client
	cfg    *config.Config
}

// NewK8sFacade initializes the Kubernetes controller-runtime client with the CRD scheme.
func NewK8sFacade(cfg *config.Config) (*K8sFacade, error) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("add corev1 to scheme: %w", err)
	}
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("add v1alpha1 to scheme: %w", err)
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.KubeconfigPath != "" {
		loadingRules.ExplicitPath = cfg.KubeconfigPath
	}
	configOverrides := &clientcmd.ConfigOverrides{}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)

	restCfg, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("build rest config: %w", err)
	}

	k8sClient, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create k8s client: %w", err)
	}

	return &K8sFacade{
		client: k8sClient,
		cfg:    cfg,
	}, nil
}

// ListProfiles returns all available AccessProfiles in capability form.
func (f *K8sFacade) ListProfiles(ctx context.Context) ([]ProfileDTO, error) {
	var profileList v1alpha1.AccessProfileList
	if err := f.client.List(ctx, &profileList); err != nil {
		return nil, fmt.Errorf("list access profiles: %w", err)
	}

	var profiles []ProfileDTO
	for _, p := range profileList.Items {
		isReady := true
		for _, cond := range p.Status.Conditions {
			if cond.Type == "Ready" && cond.Status != metav1.ConditionTrue {
				isReady = false
				break
			}
		}

		desc := fmt.Sprintf("Grants %s in namespace '%s' (Max: %s)", p.Spec.RoleRef.Name, p.Spec.TargetNamespace, p.Spec.MaxDuration)
		if p.Annotations != nil && p.Annotations["description"] != "" {
			desc = p.Annotations["description"]
		}

		profiles = append(profiles, ProfileDTO{
			Name:            p.Name,
			TargetNamespace: p.Spec.TargetNamespace,
			MaxDuration:     p.Spec.MaxDuration,
			DeliveryMode:    string(p.Spec.EffectiveDeliveryMode()),
			RoleRef:         p.Spec.RoleRef.Name,
			Description:     desc,
			IsReady:         isReady,
		})
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	return profiles, nil
}

// CreateRequest submits a new BreakGlassRequest bound to the authenticated user.
func (f *K8sFacade) CreateRequest(ctx context.Context, user *auth.UserSession, input CreateRequestInput) (*RequestDTO, error) {
	var profile v1alpha1.AccessProfile
	if err := f.client.Get(ctx, types.NamespacedName{Name: input.AccessProfile}, &profile); err != nil {
		return nil, ErrProfileNotFound
	}

	// Validate duration
	reqDuration, err := time.ParseDuration(input.Duration)
	if err != nil {
		return nil, fmt.Errorf("invalid duration format: %w", err)
	}
	maxDuration, err := time.ParseDuration(profile.Spec.MaxDuration)
	if err == nil && reqDuration > maxDuration {
		return nil, fmt.Errorf("%w: requested %s > max %s", ErrInvalidDuration, input.Duration, profile.Spec.MaxDuration)
	}

	cleanProfileName := strings.ToLower(input.AccessProfile)
	if len(cleanProfileName) > 20 {
		cleanProfileName = cleanProfileName[:20]
	}

	reqObj := &v1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("bgr-%s-", cleanProfileName),
		},
		Spec: v1alpha1.BreakGlassRequestSpec{
			AccessProfile:    profile.Name,
			AccessProfileUID: string(profile.UID),
			Requester: v1alpha1.SubjectReference{
				Kind: v1alpha1.SubjectKindUser,
				Name: user.Subject,
			},
			Duration:   input.Duration,
			RequestTTL: "15m",
			Reason:     strings.TrimSpace(input.Reason),
		},
	}

	if err := f.client.Create(ctx, reqObj); err != nil {
		return nil, fmt.Errorf("create breakglass request: %w", err)
	}

	return &RequestDTO{
		Name:            reqObj.Name,
		UID:             string(reqObj.UID),
		AccessProfile:   reqObj.Spec.AccessProfile,
		TargetNamespace: profile.Spec.TargetNamespace,
		Requester:       user.Subject,
		Duration:        reqObj.Spec.Duration,
		Reason:          reqObj.Spec.Reason,
		Phase:           string(v1alpha1.RequestPhasePending),
		CreatedAt:       reqObj.CreationTimestamp.Time,
	}, nil
}

// ListMyRequests filters requests strictly by authenticated user (P0 privacy solution).
func (f *K8sFacade) ListMyRequests(ctx context.Context, user *auth.UserSession) ([]RequestDTO, error) {
	var reqList v1alpha1.BreakGlassRequestList
	if err := f.client.List(ctx, &reqList); err != nil {
		return nil, fmt.Errorf("list requests: %w", err)
	}

	var sessionList v1alpha1.BreakGlassSessionList
	_ = f.client.List(ctx, &sessionList)
	sessionsByReq := make(map[string]v1alpha1.BreakGlassSession)
	for _, s := range sessionList.Items {
		if s.Spec.RequestRef != nil && s.Spec.RequestRef.Name != "" {
			sessionsByReq[s.Spec.RequestRef.Name] = s
		}
	}

	var profileList v1alpha1.AccessProfileList
	_ = f.client.List(ctx, &profileList)
	targetNsByProfile := make(map[string]string)
	for _, p := range profileList.Items {
		targetNsByProfile[p.Name] = p.Spec.TargetNamespace
	}

	var results []RequestDTO
	for _, r := range reqList.Items {
		// Strict identity filtering
		if r.Spec.Requester.Name != user.Subject && (user.Email == "" || r.Spec.Requester.Name != user.Email) {
			continue
		}

		dto := RequestDTO{
			Name:            r.Name,
			UID:             string(r.UID),
			AccessProfile:   r.Spec.AccessProfile,
			TargetNamespace: targetNsByProfile[r.Spec.AccessProfile],
			Requester:       r.Spec.Requester.Name,
			Duration:        r.Spec.Duration,
			Reason:          r.Spec.Reason,
			Phase:           string(r.Status.Phase),
			CreatedAt:       r.CreationTimestamp.Time,
		}

		if r.Status.ExpiresAt != nil {
			t := r.Status.ExpiresAt.Time
			dto.ExpiresAt = &t
		}
		if r.Status.ApprovalRef != nil {
			dto.Approver = r.Status.ApprovalRef.Name
		}

		// Attach associated active session data if present
		if sess, ok := sessionsByReq[r.Name]; ok {
			dto.SessionName = sess.Name
			dto.SessionPhase = string(sess.Status.Phase)
			if sess.Status.ExpiresAt != nil {
				t := sess.Status.ExpiresAt.Time
				dto.SessionExpiresAt = &t
			}
			if sess.Status.Phase == v1alpha1.PhaseActive {
				dto.CanRevoke = true
			}
		}

		results = append(results, dto)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.After(results[j].CreatedAt)
	})

	return results, nil
}

// RevokeRequest initiates immediate user revocation of an active session.
func (f *K8sFacade) RevokeRequest(ctx context.Context, user *auth.UserSession, requestName string) error {
	var reqObj v1alpha1.BreakGlassRequest
	if err := f.client.Get(ctx, types.NamespacedName{Name: requestName}, &reqObj); err != nil {
		return ErrRequestNotFound
	}

	// Strict identity check
	if reqObj.Spec.Requester.Name != user.Subject && (user.Email == "" || reqObj.Spec.Requester.Name != user.Email) {
		return ErrForbidden
	}

	// Locate associated BreakGlassSession
	var sessionList v1alpha1.BreakGlassSessionList
	if err := f.client.List(ctx, &sessionList); err != nil {
		return fmt.Errorf("list sessions: %w", err)
	}

	var targetSession *v1alpha1.BreakGlassSession
	for i := range sessionList.Items {
		s := &sessionList.Items[i]
		if s.Spec.RequestRef != nil && s.Spec.RequestRef.Name == reqObj.Name {
			targetSession = s
			break
		}
	}

	if targetSession == nil {
		return ErrSessionNotFound
	}

	if targetSession.Spec.Revoked {
		return nil // Already revoked
	}

	targetSession.Spec.Revoked = true
	if err := f.client.Update(ctx, targetSession); err != nil {
		return fmt.Errorf("update session revoked status: %w", err)
	}

	return nil
}

// ListPendingApprovals lists pending requests for eligible approvers (excluding self-requests).
func (f *K8sFacade) ListPendingApprovals(ctx context.Context, user *auth.UserSession) ([]RequestDTO, error) {
	var reqList v1alpha1.BreakGlassRequestList
	if err := f.client.List(ctx, &reqList); err != nil {
		return nil, fmt.Errorf("list requests: %w", err)
	}

	var profileList v1alpha1.AccessProfileList
	_ = f.client.List(ctx, &profileList)
	targetNsByProfile := make(map[string]string)
	for _, p := range profileList.Items {
		targetNsByProfile[p.Name] = p.Spec.TargetNamespace
	}

	var results []RequestDTO
	for _, r := range reqList.Items {
		// Only pending requests
		if r.Status.Phase != "" && r.Status.Phase != v1alpha1.RequestPhasePending {
			continue
		}

		// Anti-Self-Approval: Requester cannot approve own request
		if r.Spec.Requester.Name == user.Subject || (user.Email != "" && r.Spec.Requester.Name == user.Email) {
			continue
		}

		dto := RequestDTO{
			Name:            r.Name,
			UID:             string(r.UID),
			AccessProfile:   r.Spec.AccessProfile,
			TargetNamespace: targetNsByProfile[r.Spec.AccessProfile],
			Requester:       r.Spec.Requester.Name,
			Duration:        r.Spec.Duration,
			Reason:          r.Spec.Reason,
			Phase:           string(v1alpha1.RequestPhasePending),
			CreatedAt:       r.CreationTimestamp.Time,
			CanApprove:      true,
		}

		if r.Status.ExpiresAt != nil {
			t := r.Status.ExpiresAt.Time
			dto.ExpiresAt = &t
		}

		results = append(results, dto)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].CreatedAt.Before(results[j].CreatedAt)
	})

	return results, nil
}

// CreateApproval submits an append-only BreakGlassApproval record.
func (f *K8sFacade) CreateApproval(ctx context.Context, user *auth.UserSession, input CreateApprovalInput) error {
	var reqObj v1alpha1.BreakGlassRequest
	if err := f.client.Get(ctx, types.NamespacedName{Name: input.RequestName}, &reqObj); err != nil {
		return ErrRequestNotFound
	}

	// Enforce 4-eyes principle (Anti-Self-Approval)
	if reqObj.Spec.Requester.Name == user.Subject || (user.Email != "" && reqObj.Spec.Requester.Name == user.Email) {
		return ErrSelfApproval
	}

	decision := v1alpha1.ApprovalDecisionApproved
	if strings.EqualFold(input.Decision, "denied") {
		decision = v1alpha1.ApprovalDecisionDenied
	}

	approval := &v1alpha1.BreakGlassApproval{
		ObjectMeta: metav1.ObjectMeta{
			Name: v1alpha1.ApprovalNameForRequestUID(string(reqObj.UID)),
		},
		Spec: v1alpha1.BreakGlassApprovalSpec{
			RequestRef: v1alpha1.BreakGlassRequestReference{
				Name: reqObj.Name,
				UID:  string(reqObj.UID),
			},
			Decision: decision,
			Approver: v1alpha1.SubjectReference{
				Kind: v1alpha1.SubjectKindUser,
				Name: user.Subject,
			},
			Comment: strings.TrimSpace(input.Comment),
		},
	}

	if err := f.client.Create(ctx, approval); err != nil {
		return fmt.Errorf("create breakglass approval: %w", err)
	}

	return nil
}
