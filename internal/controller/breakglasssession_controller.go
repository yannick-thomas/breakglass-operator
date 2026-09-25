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

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
)

const (
	// BreakGlassFinalizer ensures that RBAC bindings are deleted when the session CR is deleted.
	BreakGlassFinalizer = "access.breakglass.io/finalizer"
	// Label keys used for self-healing and ownership tracking.
	ManagedByLabelKey   = "app.kubernetes.io/managed-by"
	ManagedByLabelValue = "breakglass-operator"
	SessionLabelKey     = "access.breakglass.io/session"
)

// BreakGlassSessionReconciler reconciles a BreakGlassSession object
type BreakGlassSessionReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=access.breakglass.io,resources=breakglasssessions/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=clusterrolebindings;rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile coordinates the lifecycle of BreakGlassSessions:
// 1. Ensures finalizers are attached for clean deprovisioning
// 2. Checks if an active session has expired and removes permissions
// 3. Handles manual early revocation (spec.Revoked = true)
// 4. Activates pending sessions by creating RoleBindings or ClusterRoleBindings
// 5. Schedules a requeue for the exact moment the session expires
func (r *BreakGlassSessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	// 1. Fetch the BreakGlassSession
	session := &accessv1alpha1.BreakGlassSession{}
	if err := r.Get(ctx, req.NamespacedName, session); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// 2. Handle Deletion (CR is being deleted)
	if !session.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(session, BreakGlassFinalizer) {
			log.Info("Cleaning up RBAC bindings for deleted BreakGlassSession", "session", session.Name)
			if err := r.cleanupBinding(ctx, session); err != nil {
				return ctrl.Result{}, err
			}
			controllerutil.RemoveFinalizer(session, BreakGlassFinalizer)
			if err := r.Update(ctx, session); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure Finalizer is present to prevent orphan RBAC bindings
	if !controllerutil.ContainsFinalizer(session, BreakGlassFinalizer) {
		controllerutil.AddFinalizer(session, BreakGlassFinalizer)
		if err := r.Update(ctx, session); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// 3. Handle Manual Revocation (spec.Revoked == true)
	if session.Spec.Revoked {
		if session.Status.Phase != accessv1alpha1.PhaseRevoked {
			log.Info("Session manually revoked by administrator", "session", session.Name)
			if err := r.cleanupBinding(ctx, session); err != nil {
				return ctrl.Result{}, err
			}
			session.Status.Phase = accessv1alpha1.PhaseRevoked
			if r.Recorder != nil {
				r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessRevoked", "Emergency access manually revoked by admin")
			}
			if err := r.Status().Update(ctx, session); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// 4. Handle Terminal Phase: Already Expired
	if session.Status.Phase == accessv1alpha1.PhaseExpired {
		if err := r.cleanupBinding(ctx, session); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	// 5. Expiration Check for currently active sessions
	if session.Status.ExpiresAt != nil {
		now := time.Now()
		if now.After(session.Status.ExpiresAt.Time) || now.Equal(session.Status.ExpiresAt.Time) {
			log.Info("Session duration expired, revoking RBAC access", "session", session.Name)
			if err := r.cleanupBinding(ctx, session); err != nil {
				return ctrl.Result{}, err
			}
			session.Status.Phase = accessv1alpha1.PhaseExpired
			if r.Recorder != nil {
				r.Recorder.Eventf(session, corev1.EventTypeWarning, "AccessExpired",
					"Emergency access expired at %s", session.Status.ExpiresAt.Format(time.RFC3339))
			}
			if err := r.Status().Update(ctx, session); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		// Session is still valid: ensure RBAC binding exists (self-healing / drift detection)
		if err := r.ensureBinding(ctx, session); err != nil {
			return ctrl.Result{}, err
		}

		remaining := time.Until(session.Status.ExpiresAt.Time)
		log.Info("Session is active, requeue scheduled", "session", session.Name, "requeueAfter", remaining)
		return ctrl.Result{RequeueAfter: remaining}, nil
	}

	// 6. First Activation: Parse duration and initialize status
	duration, err := time.ParseDuration(session.Spec.Duration)
	if err != nil {
		log.Error(err, "Invalid duration format in session spec", "duration", session.Spec.Duration)
		if r.Recorder != nil {
			r.Recorder.Eventf(session, corev1.EventTypeWarning, "InvalidDuration",
				"Invalid duration format %q: %v", session.Spec.Duration, err)
		}
		return ctrl.Result{}, nil
	}

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(duration))
	bindingName := fmt.Sprintf("breakglass-%s", session.Name)

	session.Status.BindingName = bindingName
	session.Status.StartTime = &now
	session.Status.ExpiresAt = &expiresAt
	session.Status.Phase = accessv1alpha1.PhaseActive

	// Create the RBAC RoleBinding or ClusterRoleBinding
	if err := r.ensureBinding(ctx, session); err != nil {
		return ctrl.Result{}, err
	}

	targetDesc := "cluster-wide"
	if session.Spec.TargetNamespace != "" {
		targetDesc = fmt.Sprintf("namespace %q", session.Spec.TargetNamespace)
	}

	if r.Recorder != nil {
		r.Recorder.Eventf(session, corev1.EventTypeNormal, "AccessGranted",
			"Granted %s %q access on %s to %s %q until %s (Reason: %s)",
			session.Spec.RoleRef.Kind, session.Spec.RoleRef.Name, targetDesc,
			session.Spec.Subject.Kind, session.Spec.Subject.Name,
			expiresAt.Format(time.RFC3339), session.Spec.Reason)
	}

	if err := r.Status().Update(ctx, session); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("BreakGlassSession activated successfully", "session", session.Name, "expiresAt", expiresAt)
	return ctrl.Result{RequeueAfter: duration}, nil
}

// ensureBinding creates or updates the required RoleBinding or ClusterRoleBinding
func (r *BreakGlassSessionReconciler) ensureBinding(ctx context.Context, session *accessv1alpha1.BreakGlassSession) error {
	bindingName := session.Status.BindingName
	if bindingName == "" {
		bindingName = fmt.Sprintf("breakglass-%s", session.Name)
	}

	subject := rbacv1.Subject{
		Kind: string(session.Spec.Subject.Kind),
		Name: session.Spec.Subject.Name,
	}
	if session.Spec.Subject.Kind == accessv1alpha1.SubjectKindServiceAccount {
		if session.Spec.Subject.Namespace != "" {
			subject.Namespace = session.Spec.Subject.Namespace
		} else if session.Spec.TargetNamespace != "" {
			subject.Namespace = session.Spec.TargetNamespace
		} else {
			subject.Namespace = "default"
		}
	}

	roleRef := rbacv1.RoleRef{
		APIGroup: rbacv1.GroupName,
		Kind:     session.Spec.RoleRef.Kind,
		Name:     session.Spec.RoleRef.Name,
	}

	labels := map[string]string{
		ManagedByLabelKey: ManagedByLabelValue,
		SessionLabelKey:   session.Name,
	}

	// Case 1: Namespaced RoleBinding
	if session.Spec.TargetNamespace != "" {
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: session.Spec.TargetNamespace,
			},
		}

		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, rb, func() error {
			rb.Labels = labels
			rb.RoleRef = roleRef
			rb.Subjects = []rbacv1.Subject{subject}
			return nil
		})
		return err
	}

	// Case 2: Cluster-wide ClusterRoleBinding
	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: bindingName,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, crb, func() error {
		crb.Labels = labels
		crb.RoleRef = roleRef
		crb.Subjects = []rbacv1.Subject{subject}
		return nil
	})
	return err
}

// cleanupBinding deletes the created RoleBinding or ClusterRoleBinding
func (r *BreakGlassSessionReconciler) cleanupBinding(ctx context.Context, session *accessv1alpha1.BreakGlassSession) error {
	bindingName := session.Status.BindingName
	if bindingName == "" {
		bindingName = fmt.Sprintf("breakglass-%s", session.Name)
	}

	if session.Spec.TargetNamespace != "" {
		rb := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      bindingName,
				Namespace: session.Spec.TargetNamespace,
			},
		}
		if err := r.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		return nil
	}

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: bindingName,
		},
	}
	if err := r.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}

// findSessionForBinding maps changes in RBAC bindings back to their parent BreakGlassSession
func (r *BreakGlassSessionReconciler) findSessionForBinding(ctx context.Context, obj client.Object) []ctrl.Request {
	sessionName, ok := obj.GetLabels()[SessionLabelKey]
	if !ok || sessionName == "" {
		return nil
	}
	return []ctrl.Request{
		{NamespacedName: types.NamespacedName{Name: sessionName}},
	}
}

// SetupWithManager sets up the controller with the Manager and watches both CRD and RBAC bindings.
func (r *BreakGlassSessionReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&accessv1alpha1.BreakGlassSession{}).
		Watches(
			&rbacv1.ClusterRoleBinding{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionForBinding),
		).
		Watches(
			&rbacv1.RoleBinding{},
			handler.EnqueueRequestsFromMapFunc(r.findSessionForBinding),
		).
		Named("breakglasssession").
		Complete(r)
}
