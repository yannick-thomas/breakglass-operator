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
	"fmt"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

const (
	// AccessProfileReadyCondition reports whether the configured manager can
	// safely activate new sessions for a profile.
	AccessProfileReadyCondition = "Ready"

	// accessProfileClusterRoleField indexes profiles by the curated role whose
	// availability determines their readiness.
	accessProfileClusterRoleField = ".spec.roleRef.name"
)

// AccessProfileReconciler evaluates administrator-owned policies before an
// incident. It does not authorize users or alter a profile's immutable spec.
type AccessProfileReconciler struct {
	client.Client
	// APIReader bypasses the cache for the curated role check. A stale role must
	// not make a profile appear ready.
	APIReader client.Reader
	Scheme    *runtime.Scheme
	// AllowedTargetNamespaces limits the namespaces in which this manager can
	// create RoleBindings. An empty set is the documented development default.
	AllowedTargetNamespaces map[string]struct{}
}

func (r *AccessProfileReconciler) policyReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// +kubebuilder:rbac:groups=access.breakglass.io,resources=accessprofiles,verbs=get;list;watch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=accessprofiles/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterroles,verbs=get

// Reconcile records whether the immutable policy is usable by this manager.
// Transient API failures are surfaced as Unknown and retried; invalid policy
// configuration is surfaced as False without a hot reconciliation loop.
func (r *AccessProfileReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	profile := &accessv1alpha1.AccessProfile{}
	if err := r.Get(ctx, req.NamespacedName, profile); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	status, reason, message, err := r.evaluateReadiness(ctx, profile)
	if err != nil {
		r.setReadyCondition(profile, metav1.ConditionUnknown, "ClusterRoleCheckFailed", "Could not verify the referenced ClusterRole")
		if updateErr := r.updateStatusIfChanged(ctx, profile); updateErr != nil {
			return ctrl.Result{}, updateErr
		}
		return ctrl.Result{}, err
	}

	r.setReadyCondition(profile, status, reason, message)
	return ctrl.Result{}, r.updateStatusIfChanged(ctx, profile)
}

func (r *AccessProfileReconciler) evaluateReadiness(
	ctx context.Context,
	profile *accessv1alpha1.AccessProfile,
) (metav1.ConditionStatus, string, string, error) {
	if profile.Spec.RoleRef.Kind != "ClusterRole" || profile.Spec.RoleRef.Name == "" {
		return metav1.ConditionFalse, "InvalidRoleReference", "The profile must reference a named curated ClusterRole", nil
	}
	if profile.Spec.TargetNamespace == "" {
		return metav1.ConditionFalse, "InvalidTargetNamespace", "The profile must specify a target namespace", nil
	}
	if duration, err := time.ParseDuration(profile.Spec.MaxDuration); err != nil || duration <= 0 {
		return metav1.ConditionFalse, "InvalidDuration", "The profile must specify a positive maximum duration", nil
	}
	if !r.targetNamespaceAllowed(profile.Spec.TargetNamespace) {
		return metav1.ConditionFalse, "NamespaceOutOfScope", fmt.Sprintf("Target namespace %q is outside this manager's allowed namespace set", profile.Spec.TargetNamespace), nil
	}

	role := &rbacv1.ClusterRole{}
	if err := r.policyReader().Get(ctx, client.ObjectKey{Name: profile.Spec.RoleRef.Name}, role); err != nil {
		if apierrors.IsNotFound(err) {
			return metav1.ConditionFalse, "ClusterRoleMissing", fmt.Sprintf("Referenced ClusterRole %q does not exist", profile.Spec.RoleRef.Name), nil
		}
		return metav1.ConditionUnknown, "ClusterRoleCheckFailed", "Could not verify the referenced ClusterRole", err
	}
	if role.UID == "" {
		return metav1.ConditionFalse, "ClusterRoleNotReady", fmt.Sprintf("Referenced ClusterRole %q has no server-assigned UID", role.Name), nil
	}

	return metav1.ConditionTrue, "Ready", "The profile can be activated by this manager", nil
}

func (r *AccessProfileReconciler) targetNamespaceAllowed(namespace string) bool {
	if len(r.AllowedTargetNamespaces) == 0 {
		return true
	}
	_, allowed := r.AllowedTargetNamespaces[namespace]
	return allowed
}

func accessProfileClusterRoleIndex(obj client.Object) []string {
	profile, ok := obj.(*accessv1alpha1.AccessProfile)
	if !ok || profile.Spec.RoleRef.Kind != "ClusterRole" || profile.Spec.RoleRef.Name == "" {
		return nil
	}
	return []string{profile.Spec.RoleRef.Name}
}

func (r *AccessProfileReconciler) setReadyCondition(
	profile *accessv1alpha1.AccessProfile,
	status metav1.ConditionStatus,
	reason, message string,
) {
	profile.Status.ObservedGeneration = profile.Generation
	meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
		Type:               AccessProfileReadyCondition,
		Status:             status,
		ObservedGeneration: profile.Generation,
		Reason:             reason,
		Message:            message,
	})
}

func (r *AccessProfileReconciler) updateStatusIfChanged(ctx context.Context, profile *accessv1alpha1.AccessProfile) error {
	stored := &accessv1alpha1.AccessProfile{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(profile), stored); err != nil {
		return err
	}
	if equality.Semantic.DeepEqual(stored.Status, profile.Status) {
		return nil
	}
	stored.Status = profile.Status
	return r.Status().Update(ctx, stored)
}

func (r *AccessProfileReconciler) findProfilesForClusterRole(ctx context.Context, obj client.Object) []ctrl.Request {
	role, ok := obj.(*rbacv1.ClusterRole)
	if !ok || role.Name == "" {
		return nil
	}

	profiles := &accessv1alpha1.AccessProfileList{}
	if err := r.List(ctx, profiles, client.MatchingFields{accessProfileClusterRoleField: role.Name}); err != nil {
		return nil
	}
	requests := make([]ctrl.Request, 0, len(profiles.Items))
	for i := range profiles.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&profiles.Items[i])})
	}
	return requests
}

// SetupWithManager sets up the readiness controller for AccessProfiles.
func (r *AccessProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &accessv1alpha1.AccessProfile{}, accessProfileClusterRoleField, accessProfileClusterRoleIndex); err != nil {
		return fmt.Errorf("index AccessProfiles by ClusterRole: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.AccessProfile{}).
		Watches(
			&rbacv1.ClusterRole{},
			handler.EnqueueRequestsFromMapFunc(r.findProfilesForClusterRole),
		).
		Named("accessprofile").
		Complete(r)
}
