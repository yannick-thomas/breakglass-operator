/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/port"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/sessionlifecycle"
)

// apiPolicySource reads policy objects. Reader must bypass the informer cache.
type apiPolicySource struct {
	Reader client.Reader
}

var _ sessionlifecycle.PolicySource = apiPolicySource{}

func (p apiPolicySource) Profile(ctx context.Context, name string) (access.Profile, error) {
	profile := &accessv1alpha1.AccessProfile{}
	if err := p.Reader.Get(ctx, client.ObjectKey{Name: name}, profile); err != nil {
		return access.Profile{}, apiconv.Classify(err)
	}
	return apiconv.ToDomainProfile(profile), nil
}

func (p apiPolicySource) Role(ctx context.Context, name string) (access.Role, error) {
	role := &rbacv1.ClusterRole{}
	if err := p.Reader.Get(ctx, client.ObjectKey{Name: name}, role); err != nil {
		return access.Role{}, apiconv.Classify(err)
	}
	return access.Role{Name: role.Name, UID: string(role.UID), RulesHash: curatedRoleRulesHash(role.Rules)}, nil
}

func (p apiPolicySource) Request(ctx context.Context, name string) (access.Request, error) {
	request := &accessv1alpha1.BreakGlassRequest{}
	if err := p.Reader.Get(ctx, client.ObjectKey{Name: name}, request); err != nil {
		return access.Request{}, apiconv.Classify(err)
	}
	return apiconv.ToDomainRequest(request), nil
}

func (p apiPolicySource) Approval(ctx context.Context, name string) (access.Approval, error) {
	approval := &accessv1alpha1.BreakGlassApproval{}
	if err := p.Reader.Get(ctx, client.ObjectKey{Name: name}, approval); err != nil {
		return access.Approval{}, apiconv.Classify(err)
	}
	return apiconv.ToDomainApproval(approval), nil
}

// NamespaceAbsent needs only get on the named namespace. The namespaced
// overlay grants exactly that, without namespace list/watch or writes.
func (p apiPolicySource) NamespaceAbsent(ctx context.Context, namespace string) bool {
	err := p.Reader.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})
	return apierrors.IsNotFound(err)
}

// curatedRoleRulesHash is a canonical digest of a role's rules. Ordering of
// rules and of values within a rule does not change it.
func curatedRoleRulesHash(rules []rbacv1.PolicyRule) string {
	canonicalRules := make([]rbacv1.PolicyRule, len(rules))
	for i, rule := range rules {
		canonicalRules[i] = rule
		slices.Sort(canonicalRules[i].APIGroups)
		slices.Sort(canonicalRules[i].Resources)
		slices.Sort(canonicalRules[i].ResourceNames)
		slices.Sort(canonicalRules[i].Verbs)
		slices.Sort(canonicalRules[i].NonResourceURLs)
	}
	slices.SortFunc(canonicalRules, func(leftRule, rightRule rbacv1.PolicyRule) int {
		left, _ := json.Marshal(leftRule)
		right, _ := json.Marshal(rightRule)
		return strings.Compare(string(left), string(right))
	})
	payload, _ := json.Marshal(canonicalRules)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

var errBindingChanged = errors.New("the RoleBinding changed since it was verified")

// roleBindingGateway writes RoleBindings. Client serves cached reads and all
// writes; Lister lists directly from the API server.
type roleBindingGateway struct {
	Client client.Client
	Lister client.Reader
}

var _ sessionlifecycle.BindingGateway = roleBindingGateway{}

func (g roleBindingGateway) Create(ctx context.Context, draft sessionlifecycle.BindingDraft) (access.Binding, error) {
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:            draft.Name,
			Namespace:       draft.Namespace,
			Labels:          draft.Labels,
			OwnerReferences: []metav1.OwnerReference{apiconv.SessionControllerOwner(draft.Owner)},
		},
		RoleRef:  rbacv1.RoleRef{APIGroup: draft.RoleRef.APIGroup, Kind: draft.RoleRef.Kind, Name: draft.RoleRef.Name},
		Subjects: apiconv.ToAPISubjects(draft.Subjects),
	}
	if err := g.Client.Create(ctx, rb); err != nil {
		return access.Binding{}, apiconv.Classify(err)
	}
	return apiconv.ToDomainBinding(rb), nil
}

func (g roleBindingGateway) Get(ctx context.Context, namespace, name string) (access.Binding, error) {
	rb := &rbacv1.RoleBinding{}
	if err := g.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, rb); err != nil {
		return access.Binding{}, apiconv.Classify(err)
	}
	return apiconv.ToDomainBinding(rb), nil
}

// SetSubjects re-reads the binding and updates it only if it is still the
// observed version, so a concurrent change fails instead of being overwritten.
func (g roleBindingGateway) SetSubjects(ctx context.Context, binding access.Binding, subjects []access.BindingSubject) error {
	rb := &rbacv1.RoleBinding{}
	if err := g.Client.Get(ctx, client.ObjectKey{Namespace: binding.Namespace, Name: binding.Name}, rb); err != nil {
		return apiconv.Classify(err)
	}
	if string(rb.UID) != binding.UID || rb.ResourceVersion != binding.Version {
		return port.Mark(port.ErrConflict, apierrors.NewConflict(rbacv1.Resource("rolebindings"), binding.Name,
			errBindingChanged))
	}
	rb.Subjects = apiconv.ToAPISubjects(subjects)
	return apiconv.Classify(g.Client.Update(ctx, rb))
}

func (g roleBindingGateway) Delete(ctx context.Context, ref access.BindingRef) error {
	uid := types.UID(ref.UID)
	rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name}}
	return apiconv.Classify(g.Client.Delete(ctx, rb, client.Preconditions{UID: &uid}))
}

func (g roleBindingGateway) ListManaged(ctx context.Context, namespace string, labels map[string]string) ([]access.Binding, error) {
	list := &rbacv1.RoleBindingList{}
	options := []client.ListOption{client.MatchingLabels(labels)}
	if namespace != "" {
		options = append(options, client.InNamespace(namespace))
	}
	if err := g.Lister.List(ctx, list, options...); err != nil {
		return nil, apiconv.Classify(err)
	}
	bindings := make([]access.Binding, len(list.Items))
	for i := range list.Items {
		bindings[i] = apiconv.ToDomainBinding(&list.Items[i])
	}
	return bindings, nil
}

// sessionStore persists one session object.
type sessionStore struct {
	Client client.Client
	Object *accessv1alpha1.BreakGlassSession
}

var _ sessionlifecycle.SessionStore = sessionStore{}

func (s sessionStore) UpdateStatus(ctx context.Context, session *access.Session) error {
	apiconv.ApplySessionStatus(session, s.Object)
	return s.Client.Status().Update(ctx, s.Object)
}

func (s sessionStore) AddFinalizer(ctx context.Context, session *access.Session) error {
	controllerutil.AddFinalizer(s.Object, access.Finalizer)
	if err := s.Client.Update(ctx, s.Object); err != nil {
		return err
	}
	session.HasFinalizer = true
	return nil
}

func (s sessionStore) RemoveFinalizer(ctx context.Context, session *access.Session) error {
	controllerutil.RemoveFinalizer(s.Object, access.Finalizer)
	if err := s.Client.Update(ctx, s.Object); err != nil {
		return err
	}
	session.HasFinalizer = false
	return nil
}

// sessionEvents records events on one session object.
type sessionEvents struct {
	Recorder record.EventRecorder
	Object   *accessv1alpha1.BreakGlassSession
}

func (e sessionEvents) Event(eventType, reason, messageFmt string, args ...any) {
	if e.Recorder != nil {
		e.Recorder.Eventf(e.Object, eventType, reason, messageFmt, args...)
	}
}
