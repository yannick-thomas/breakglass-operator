package facade

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"

	"github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/auth"
	"github.com/yannick-thomas/breakglass-operator/internal/webui/config"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrSelfApproval  = errors.New("requester cannot decide on their own request")
	ErrNotPending    = errors.New("request is no longer pending")
	ErrNotRevocable  = errors.New("session has already ended")
	ErrInvalidInput  = errors.New("invalid input")
	ErrNoCredentials = errors.New("no user credential available")
)

const descriptionAnnotation = "description"

// ProfileDTO is a capability-oriented view of an AccessProfile the person may use.
// Namespace is the profile's control namespace; it identifies the profile
// together with Name (ADR-004).
type ProfileDTO struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	TargetNamespace string `json:"targetNamespace"`
	MaxDuration     string `json:"maxDuration"`
	DeliveryMode    string `json:"deliveryMode"`
	RoleRef         string `json:"roleRef"`
	Description     string `json:"description"`
	IsReady         bool   `json:"isReady"`
}

// AccessKind distinguishes approval-workflow requests from direct self-service sessions.
type AccessKind string

const (
	AccessKindRequest AccessKind = "Request"
	AccessKindSession AccessKind = "Session"
)

// RequestDTO is a privacy-filtered view of one access request or self-service
// session together with its approval and session state.
type RequestDTO struct {
	Kind              AccessKind `json:"kind"`
	Name              string     `json:"name"`
	Namespace         string     `json:"namespace"`
	AccessProfile     string     `json:"accessProfile"`
	TargetNamespace   string     `json:"targetNamespace"`
	Requester         string     `json:"requester"`
	Duration          string     `json:"duration"`
	Reason            string     `json:"reason"`
	Phase             string     `json:"phase"`
	CreatedAt         time.Time  `json:"createdAt"`
	ExpiresAt         *time.Time `json:"expiresAt,omitempty"`
	SessionName       string     `json:"sessionName,omitempty"`
	SessionPhase      string     `json:"sessionPhase,omitempty"`
	SessionExpiresAt  *time.Time `json:"sessionExpiresAt,omitempty"`
	SessionCreatedAt  *time.Time `json:"sessionCreatedAt,omitempty"`
	SessionRevoked    bool       `json:"sessionRevoked"`
	ApprovalDecision  string     `json:"approvalDecision,omitempty"`
	Approver          string     `json:"approver,omitempty"`
	ApprovalComment   string     `json:"approvalComment,omitempty"`
	ApprovalCreatedAt *time.Time `json:"approvalCreatedAt,omitempty"`
	CanRevoke         bool       `json:"canRevoke"`
	CanApprove        bool       `json:"canApprove"`
}

// CreateAccessInput defines user input for requesting access.
type CreateAccessInput struct {
	Namespace     string `json:"namespace"`
	AccessProfile string `json:"accessProfile"`
	Duration      string `json:"duration"`
	Reason        string `json:"reason"`
}

// CreateApprovalInput defines approver input for approving or denying a request.
type CreateApprovalInput struct {
	Namespace   string `json:"namespace"`
	RequestName string `json:"requestName"`
	Decision    string `json:"decision"`
	Comment     string `json:"comment,omitempty"`
}

// Actor is the signed-in person. Client authenticates to the API server with
// that person's own credential, so Kubernetes authorizes, admits and audits
// every write as them. Username is the identity Kubernetes reported for it.
type Actor struct {
	Username string
	Client   client.Client
}

// K8sFacade mediates between the WebUI BFF and the Kubernetes API.
//
// reader uses the WebUI ServiceAccount, which may only get/list/watch the
// BreakGlass CRDs. Kubernetes RBAC cannot filter a list by requester, so the
// facade filters strictly by the Kubernetes identity before returning data.
// Writes and authorization pre-checks never use reader.
type K8sFacade struct {
	reader client.Reader
	scheme *runtime.Scheme
	base   *rest.Config
	mapper meta.RESTMapper
	// devClient is the developer's kubeconfig identity; set only in dev mode.
	devClient client.Client
}

// NewK8sFacade builds the read-only facade client and the factory for user clients.
func NewK8sFacade(cfg *config.Config) (*K8sFacade, error) {
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		v1alpha1.AddToScheme,
		authenticationv1.AddToScheme,
		authorizationv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			return nil, fmt.Errorf("build scheme: %w", err)
		}
	}

	base, err := loadRESTConfig(cfg)
	if err != nil {
		return nil, err
	}
	httpClient, err := rest.HTTPClientFor(base)
	if err != nil {
		return nil, fmt.Errorf("create HTTP client: %w", err)
	}
	mapper, err := apiutil.NewDynamicRESTMapper(base, httpClient)
	if err != nil {
		return nil, fmt.Errorf("create REST mapper: %w", err)
	}
	reader, err := client.New(base, client.Options{Scheme: scheme, Mapper: mapper, HTTPClient: httpClient})
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}

	f := &K8sFacade{reader: reader, scheme: scheme, base: base, mapper: mapper}
	if cfg.DevMode {
		f.devClient = reader
	}
	return f, nil
}

func loadRESTConfig(cfg *config.Config) (*rest.Config, error) {
	if cfg.InCluster {
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("load in-cluster config: %w", err)
		}
		return restCfg, nil
	}
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cfg.KubeconfigPath != "" {
		loadingRules.ExplicitPath = cfg.KubeconfigPath
	}
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	return restCfg, nil
}

// ClientForToken returns a client that authenticates only with the given
// bearer token. AnonymousClientConfig strips the ServiceAccount credential.
func (f *K8sFacade) ClientForToken(token string) (client.Client, error) {
	if token == "" {
		return nil, ErrNoCredentials
	}
	restCfg := rest.AnonymousClientConfig(f.base)
	restCfg.BearerToken = token
	return client.New(restCfg, client.Options{Scheme: f.scheme, Mapper: f.mapper})
}

// DevClient returns the developer's kubeconfig client in dev mode.
func (f *K8sFacade) DevClient() (client.Client, error) {
	if f.devClient == nil {
		return nil, ErrNoCredentials
	}
	return f.devClient, nil
}

// Whoami asks the API server who the credential belongs to. This is the
// identity admission will record, independent of OIDC claim mapping.
func Whoami(ctx context.Context, c client.Client) (auth.Identity, error) {
	review := &authenticationv1.SelfSubjectReview{}
	if err := c.Create(ctx, review); err != nil {
		return auth.Identity{}, fmt.Errorf("create SelfSubjectReview: %w", err)
	}
	info := review.Status.UserInfo
	if info.Username == "" {
		return auth.Identity{}, errors.New("API server returned no username")
	}
	return auth.Identity{Username: info.Username, Groups: info.Groups}, nil
}

// ListProfiles returns the AccessProfiles the person is allowed to use.
// Profile names and target namespaces can be sensitive, so a profile without
// the "use" permission is not shown at all.
func (f *K8sFacade) ListProfiles(ctx context.Context, actor Actor) ([]ProfileDTO, error) {
	var profileList v1alpha1.AccessProfileList
	if err := f.reader.List(ctx, &profileList); err != nil {
		return nil, fmt.Errorf("list AccessProfiles: %w", err)
	}

	profiles := []ProfileDTO{}
	for _, p := range profileList.Items {
		allowed, err := canAccessProfile(ctx, actor, "use", p.Namespace, p.Name)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}

		desc := fmt.Sprintf("Grants %s in namespace '%s' (Max: %s)", p.Spec.RoleRef.Name, p.Spec.TargetNamespace, p.Spec.MaxDuration)
		if d := p.Annotations[descriptionAnnotation]; d != "" {
			desc = d
		}

		profiles = append(profiles, ProfileDTO{
			Name:            p.Name,
			Namespace:       p.Namespace,
			TargetNamespace: p.Spec.TargetNamespace,
			MaxDuration:     p.Spec.MaxDuration,
			DeliveryMode:    string(p.Spec.EffectiveDeliveryMode()),
			RoleRef:         p.Spec.RoleRef.Name,
			Description:     desc,
			IsReady:         meta.IsStatusConditionTrue(p.Status.Conditions, "Ready"),
		})
	}

	slices.SortFunc(profiles, func(a, b ProfileDTO) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Namespace, b.Namespace))
	})
	return profiles, nil
}

// CreateAccess submits intent as the signed-in person: a BreakGlassRequest for
// approval-required profiles, or a BreakGlassSession for self-service ones.
// Admission overwrites requester and profile UID from the authenticated
// request and remains the only authority on profile use and duration.
func (f *K8sFacade) CreateAccess(ctx context.Context, actor Actor, input CreateAccessInput) (*RequestDTO, error) {
	input.Reason = strings.TrimSpace(input.Reason)
	if input.Namespace == "" || input.AccessProfile == "" || input.Duration == "" || input.Reason == "" {
		return nil, fmt.Errorf("%w: namespace, accessProfile, duration and reason are required", ErrInvalidInput)
	}
	if d, err := time.ParseDuration(input.Duration); err != nil || d <= 0 {
		return nil, fmt.Errorf("%w: duration must be a positive duration such as 30m", ErrInvalidInput)
	}

	var profile v1alpha1.AccessProfile
	if err := f.reader.Get(ctx, types.NamespacedName{Namespace: input.Namespace, Name: input.AccessProfile}, &profile); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get AccessProfile: %w", err)
	}
	subject := v1alpha1.SubjectReference{Kind: v1alpha1.SubjectKindUser, Name: actor.Username}

	if profile.Spec.EffectiveDeliveryMode() == v1alpha1.AccessDeliveryModeSelfService {
		sess := &v1alpha1.BreakGlassSession{
			ObjectMeta: metav1.ObjectMeta{Namespace: profile.Namespace, GenerateName: "bgs-"},
			Spec: v1alpha1.BreakGlassSessionSpec{
				AccessProfile: profile.Name,
				Subject:       subject,
				Duration:      input.Duration,
				Reason:        input.Reason,
			},
		}
		if err := actor.Client.Create(ctx, sess); err != nil {
			return nil, fmt.Errorf("create BreakGlassSession: %w", err)
		}
		dto := sessionDTO(sess, profile.Spec.TargetNamespace)
		return &dto, nil
	}

	req := &v1alpha1.BreakGlassRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: profile.Namespace, GenerateName: "bgr-"},
		Spec: v1alpha1.BreakGlassRequestSpec{
			AccessProfile: profile.Name,
			Requester:     subject,
			Duration:      input.Duration,
			Reason:        input.Reason,
		},
	}
	if err := actor.Client.Create(ctx, req); err != nil {
		return nil, fmt.Errorf("create BreakGlassRequest: %w", err)
	}
	dto := requestDTO(req, profile.Spec.TargetNamespace)
	return &dto, nil
}

// ListMine returns the person's own requests and self-service sessions.
// Matching is an exact comparison with the Kubernetes username.
func (f *K8sFacade) ListMine(ctx context.Context, username string) ([]RequestDTO, error) {
	var reqList v1alpha1.BreakGlassRequestList
	if err := f.reader.List(ctx, &reqList); err != nil {
		return nil, fmt.Errorf("list BreakGlassRequests: %w", err)
	}
	var sessionList v1alpha1.BreakGlassSessionList
	if err := f.reader.List(ctx, &sessionList); err != nil {
		return nil, fmt.Errorf("list BreakGlassSessions: %w", err)
	}
	var approvalList v1alpha1.BreakGlassApprovalList
	if err := f.reader.List(ctx, &approvalList); err != nil {
		return nil, fmt.Errorf("list BreakGlassApprovals: %w", err)
	}
	namespaces, err := f.profileNamespaces(ctx)
	if err != nil {
		return nil, err
	}

	sessionsByRequestUID := make(map[string]*v1alpha1.BreakGlassSession)
	results := []RequestDTO{}
	for i := range sessionList.Items {
		s := &sessionList.Items[i]
		if s.Spec.RequestRef != nil {
			sessionsByRequestUID[s.Spec.RequestRef.UID] = s
			continue
		}
		if isOwnSubject(s.Spec.Subject, username) {
			results = append(results, sessionDTO(s, namespaces[profileKey(s.Namespace, s.Spec.AccessProfile)]))
		}
	}
	approvalsByRequestUID := make(map[string]*v1alpha1.BreakGlassApproval)
	for i := range approvalList.Items {
		a := &approvalList.Items[i]
		approvalsByRequestUID[a.Spec.RequestRef.UID] = a
	}

	for i := range reqList.Items {
		r := &reqList.Items[i]
		if !isOwnSubject(r.Spec.Requester, username) {
			continue
		}
		dto := requestDTO(r, namespaces[profileKey(r.Namespace, r.Spec.AccessProfile)])
		if a, ok := approvalsByRequestUID[string(r.UID)]; ok {
			dto.ApprovalDecision = string(a.Spec.Decision)
			dto.Approver = a.Spec.Approver.Name
			dto.ApprovalComment = a.Spec.Comment
			t := a.CreationTimestamp.Time
			dto.ApprovalCreatedAt = &t
		}
		// Only the session the controller recorded for this request counts,
		// matched by UID so that a same-name object is never attributed.
		if r.Status.SessionRef != nil {
			if s, ok := sessionsByRequestUID[string(r.UID)]; ok && s.Name == r.Status.SessionRef.Name {
				attachSession(&dto, s)
			}
		}
		results = append(results, dto)
	}

	slices.SortFunc(results, func(a, b RequestDTO) int {
		return b.CreatedAt.Compare(a.CreatedAt)
	})
	return results, nil
}

// RevokeSession sets the one-way spec.revoked flag as the signed-in person.
// A session that does not belong to them is reported as not found, so the
// endpoint cannot be used to probe for other people's sessions.
func (f *K8sFacade) RevokeSession(ctx context.Context, actor Actor, namespace, sessionName string) error {
	var sess v1alpha1.BreakGlassSession
	if err := f.reader.Get(ctx, types.NamespacedName{Namespace: namespace, Name: sessionName}, &sess); err != nil {
		if apierrors.IsNotFound(err) {
			return ErrNotFound
		}
		return fmt.Errorf("get BreakGlassSession: %w", err)
	}
	if !isOwnSubject(sess.Spec.Subject, actor.Username) {
		return ErrNotFound
	}
	if sess.Spec.Revoked {
		return nil
	}
	if isTerminalSessionPhase(sess.Status.Phase) {
		return ErrNotRevocable
	}

	base := sess.DeepCopy()
	sess.Spec.Revoked = true
	// The optimistic lock makes the patch apply only to the exact object
	// version that was checked above.
	if err := actor.Client.Patch(ctx, &sess, client.MergeFromWithOptions(base, client.MergeFromWithOptimisticLock{})); err != nil {
		return fmt.Errorf("revoke BreakGlassSession: %w", err)
	}
	return nil
}

// ListPendingApprovals lists open requests the person may decide on: not
// their own, still pending and not expired, and for which Kubernetes grants
// them the profile-specific "approve" verb.
func (f *K8sFacade) ListPendingApprovals(ctx context.Context, actor Actor) ([]RequestDTO, error) {
	var reqList v1alpha1.BreakGlassRequestList
	if err := f.reader.List(ctx, &reqList); err != nil {
		return nil, fmt.Errorf("list BreakGlassRequests: %w", err)
	}
	namespaces, err := f.profileNamespaces(ctx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	canApprove := make(map[string]bool)
	results := []RequestDTO{}
	for i := range reqList.Items {
		r := &reqList.Items[i]
		if !isPending(r, now) || isOwnSubject(r.Spec.Requester, actor.Username) {
			continue
		}
		key := profileKey(r.Namespace, r.Spec.AccessProfile)
		allowed, seen := canApprove[key]
		if !seen {
			allowed, err = canAccessProfile(ctx, actor, "approve", r.Namespace, r.Spec.AccessProfile)
			if err != nil {
				return nil, err
			}
			canApprove[key] = allowed
		}
		if !allowed {
			continue
		}
		dto := requestDTO(r, namespaces[key])
		dto.CanApprove = true
		results = append(results, dto)
	}

	slices.SortFunc(results, func(a, b RequestDTO) int {
		return a.CreatedAt.Compare(b.CreatedAt)
	})
	return results, nil
}

// CreateApproval records one append-only decision as the signed-in person.
// The deterministic name makes concurrent decisions conflict in the API
// server; the approval webhook remains the authority on self-approval,
// permission, request UID and expiry.
func (f *K8sFacade) CreateApproval(ctx context.Context, actor Actor, input CreateApprovalInput) error {
	var decision v1alpha1.ApprovalDecision
	switch input.Decision {
	case string(v1alpha1.ApprovalDecisionApproved):
		decision = v1alpha1.ApprovalDecisionApproved
	case string(v1alpha1.ApprovalDecisionDenied):
		decision = v1alpha1.ApprovalDecisionDenied
	default:
		return fmt.Errorf("%w: decision must be Approved or Denied", ErrInvalidInput)
	}

	if input.Namespace == "" || input.RequestName == "" {
		return fmt.Errorf("%w: namespace and requestName are required", ErrInvalidInput)
	}
	var req v1alpha1.BreakGlassRequest
	if err := f.reader.Get(ctx, types.NamespacedName{Namespace: input.Namespace, Name: input.RequestName}, &req); err != nil {
		if apierrors.IsNotFound(err) {
			return ErrNotFound
		}
		return fmt.Errorf("get BreakGlassRequest: %w", err)
	}
	if isOwnSubject(req.Spec.Requester, actor.Username) {
		return ErrSelfApproval
	}
	if !isPending(&req, time.Now()) {
		return ErrNotPending
	}

	approval := &v1alpha1.BreakGlassApproval{
		ObjectMeta: metav1.ObjectMeta{Namespace: req.Namespace, Name: v1alpha1.ApprovalNameForRequestUID(string(req.UID))},
		Spec: v1alpha1.BreakGlassApprovalSpec{
			RequestRef: v1alpha1.BreakGlassRequestReference{Name: req.Name, UID: string(req.UID)},
			Decision:   decision,
			Approver:   v1alpha1.SubjectReference{Kind: v1alpha1.SubjectKindUser, Name: actor.Username},
			Comment:    strings.TrimSpace(input.Comment),
		},
	}
	if err := actor.Client.Create(ctx, approval); err != nil {
		return fmt.Errorf("create BreakGlassApproval: %w", err)
	}
	return nil
}

// profileNamespaces maps each profile, keyed by profileKey, to its target
// namespace.
func (f *K8sFacade) profileNamespaces(ctx context.Context) (map[string]string, error) {
	var profileList v1alpha1.AccessProfileList
	if err := f.reader.List(ctx, &profileList); err != nil {
		return nil, fmt.Errorf("list AccessProfiles: %w", err)
	}
	namespaces := make(map[string]string, len(profileList.Items))
	for _, p := range profileList.Items {
		namespaces[profileKey(p.Namespace, p.Name)] = p.Spec.TargetNamespace
	}
	return namespaces, nil
}

// profileKey identifies a profile across control namespaces.
func profileKey(namespace, name string) string {
	return namespace + "/" + name
}

// canAccessProfile asks the API server, with the person's own credential,
// whether they hold a profile-scoped custom verb. It mirrors the
// SubjectAccessReview that admission performs and is purely informative.
func canAccessProfile(ctx context.Context, actor Actor, verb, namespace, profile string) (bool, error) {
	review := &authorizationv1.SelfSubjectAccessReview{
		Spec: authorizationv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Group:     v1alpha1.GroupVersion.Group,
				Version:   v1alpha1.GroupVersion.Version,
				Resource:  "accessprofiles",
				Verb:      verb,
				Name:      profile,
			},
		},
	}
	if err := actor.Client.Create(ctx, review); err != nil {
		return false, fmt.Errorf("create SelfSubjectAccessReview: %w", err)
	}
	return review.Status.Allowed, nil
}

func isOwnSubject(s v1alpha1.SubjectReference, username string) bool {
	return username != "" && s.Kind == v1alpha1.SubjectKindUser && s.Name == username
}

func isPending(r *v1alpha1.BreakGlassRequest, now time.Time) bool {
	if r.Status.Phase != "" && r.Status.Phase != v1alpha1.RequestPhasePending {
		return false
	}
	return r.Status.ExpiresAt == nil || now.Before(r.Status.ExpiresAt.Time)
}

func isTerminalSessionPhase(p v1alpha1.SessionPhase) bool {
	switch p {
	case v1alpha1.PhaseExpired, v1alpha1.PhaseRevoked, v1alpha1.PhaseDenied:
		return true
	}
	return false
}

func requestDTO(r *v1alpha1.BreakGlassRequest, namespace string) RequestDTO {
	phase := r.Status.Phase
	if phase == "" {
		phase = v1alpha1.RequestPhasePending
	}
	dto := RequestDTO{
		Kind:            AccessKindRequest,
		Name:            r.Name,
		Namespace:       r.Namespace,
		AccessProfile:   r.Spec.AccessProfile,
		TargetNamespace: namespace,
		Requester:       r.Spec.Requester.Name,
		Duration:        r.Spec.Duration,
		Reason:          r.Spec.Reason,
		Phase:           string(phase),
		CreatedAt:       r.CreationTimestamp.Time,
	}
	if r.Status.ExpiresAt != nil {
		t := r.Status.ExpiresAt.Time
		dto.ExpiresAt = &t
	}
	return dto
}

func sessionDTO(s *v1alpha1.BreakGlassSession, namespace string) RequestDTO {
	dto := RequestDTO{
		Kind:            AccessKindSession,
		Name:            s.Name,
		Namespace:       s.Namespace,
		AccessProfile:   s.Spec.AccessProfile,
		TargetNamespace: namespace,
		Requester:       s.Spec.Subject.Name,
		Duration:        s.Spec.Duration,
		Reason:          s.Spec.Reason,
		CreatedAt:       s.CreationTimestamp.Time,
	}
	attachSession(&dto, s)
	dto.Phase = dto.SessionPhase
	return dto
}

func attachSession(dto *RequestDTO, s *v1alpha1.BreakGlassSession) {
	phase := s.Status.Phase
	if phase == "" {
		phase = v1alpha1.PhasePending
	}
	dto.SessionName = s.Name
	dto.SessionPhase = string(phase)
	dto.SessionRevoked = s.Spec.Revoked
	created := s.CreationTimestamp.Time
	dto.SessionCreatedAt = &created
	if s.Status.ExpiresAt != nil {
		t := s.Status.ExpiresAt.Time
		dto.SessionExpiresAt = &t
	}
	dto.CanRevoke = !s.Spec.Revoked && !isTerminalSessionPhase(phase)
}
