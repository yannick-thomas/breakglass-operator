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

// Package expiryguard adapts the expiry sweep use case to the Kubernetes API.
// The expiry-guard command runs it as a CronJob with its own ServiceAccount.
//
// Sessions and bindings are listed one namespace at a time. Besides session
// reads and RoleBinding get/list/delete, the guard needs get on its target and
// control Namespaces from a ClusterRole: that permission survives the deletion
// of any of them and lets the sweep tell a deleted namespace (Namespace
// NotFound) from one it may merely not read.
package expiryguard

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/expirysweep"
)

// New wires a sweeper to a Kubernetes client. The client must read directly
// from the API server: the guard must not act on a stale cache, and a
// namespace's absence must be observed, not remembered. The sweeper lists
// sessions in the control namespaces, or cluster-wide when none are named.
func New(c client.Client, control access.NamespaceScope) *expirysweep.Sweeper {
	return &expirysweep.Sweeper{
		Sessions:   sessionSource{Reader: c},
		Control:    control,
		Bindings:   bindingGateway{Client: c},
		Namespaces: namespaceObserver{Reader: c},
		Grace:      expirysweep.DefaultGrace,
	}
}

type sessionSource struct {
	Reader client.Reader
}

func (s sessionSource) List(ctx context.Context, namespace string) ([]access.Session, error) {
	var list accessv1alpha1.BreakGlassSessionList
	var options []client.ListOption
	if namespace != "" {
		options = append(options, client.InNamespace(namespace))
	}
	if err := s.Reader.List(ctx, &list, options...); err != nil {
		return nil, apiconv.Classify(err)
	}
	sessions := make([]access.Session, len(list.Items))
	for i := range list.Items {
		sessions[i] = *apiconv.ToDomainSession(&list.Items[i])
	}
	return sessions, nil
}

type bindingGateway struct {
	Client client.Client
}

func (g bindingGateway) Get(ctx context.Context, namespace, name string) (access.Binding, error) {
	binding := &rbacv1.RoleBinding{}
	if err := g.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, binding); err != nil {
		return access.Binding{}, apiconv.Classify(err)
	}
	return apiconv.ToDomainBinding(binding), nil
}

func (g bindingGateway) ListManaged(ctx context.Context, namespace string) ([]access.Binding, error) {
	var list rbacv1.RoleBindingList
	options := []client.ListOption{client.MatchingLabels{access.ManagedByLabelKey: access.ManagedByLabelValue}}
	if namespace != "" {
		options = append(options, client.InNamespace(namespace))
	}
	if err := g.Client.List(ctx, &list, options...); err != nil {
		return nil, apiconv.Classify(err)
	}
	bindings := make([]access.Binding, len(list.Items))
	for i := range list.Items {
		bindings[i] = apiconv.ToDomainBinding(&list.Items[i])
	}
	return bindings, nil
}

// Delete removes the binding only if neither its UID nor its content changed
// since it was verified.
func (g bindingGateway) Delete(ctx context.Context, binding access.Binding) error {
	uid := types.UID(binding.UID)
	version := binding.Version
	obj := &rbacv1.RoleBinding{}
	obj.Namespace, obj.Name = binding.Namespace, binding.Name
	return apiconv.Classify(g.Client.Delete(ctx, obj, client.Preconditions{UID: &uid, ResourceVersion: &version}))
}

type namespaceObserver struct {
	Reader client.Reader
}

// NamespaceAbsent needs only get on the named namespace. Only a direct
// NotFound counts: Forbidden or any other error is not evidence of absence,
// and a terminating namespace still exists.
func (o namespaceObserver) NamespaceAbsent(ctx context.Context, namespace string) bool {
	err := o.Reader.Get(ctx, client.ObjectKey{Name: namespace}, &corev1.Namespace{})
	return apierrors.IsNotFound(err)
}
