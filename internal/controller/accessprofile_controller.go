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
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/profilereadiness"
)

const (
	// AccessProfileReadyCondition reports whether the configured manager can
	// safely activate new sessions for a profile.
	AccessProfileReadyCondition = "Ready"

	// ProfileReadinessRetryInterval lets a profile recover when its curated role
	// is created after the profile, without granting the manager cluster-wide
	// list/watch permissions on ClusterRoles.
	ProfileReadinessRetryInterval = time.Minute
)

// AccessProfileReconciler adapts the profile readiness use case to
// controller-runtime. It does not authorize users or alter a profile's
// immutable spec.
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

	evaluator := profilereadiness.Evaluator{Roles: apiPolicySource{Reader: r.policyReader()}, Scope: r.AllowedTargetNamespaces}
	readiness, err := evaluator.Evaluate(ctx, apiconv.ToDomainProfile(profile))
	r.setReadyCondition(profile, readiness)
	if updateErr := r.updateStatusIfChanged(ctx, profile); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if readiness.Reason == profilereadiness.ReasonClusterRoleMissing {
		return ctrl.Result{RequeueAfter: ProfileReadinessRetryInterval}, nil
	}
	return ctrl.Result{}, nil
}

func (r *AccessProfileReconciler) setReadyCondition(profile *accessv1alpha1.AccessProfile, readiness profilereadiness.Readiness) {
	profile.Status.ObservedGeneration = profile.Generation
	meta.SetStatusCondition(&profile.Status.Conditions, metav1.Condition{
		Type:               AccessProfileReadyCondition,
		Status:             metav1.ConditionStatus(readiness.Status),
		ObservedGeneration: profile.Generation,
		Reason:             readiness.Reason,
		Message:            readiness.Message,
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

// SetupWithManager sets up the readiness controller for AccessProfiles.
func (r *AccessProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.AccessProfile{}).
		Named("accessprofile").
		Complete(r)
}
