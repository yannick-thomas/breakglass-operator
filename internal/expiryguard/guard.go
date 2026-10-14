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
package expiryguard

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	accessv1alpha1 "github.com/yannick-thomas/breakglass-operator/api/v1alpha1"
	"github.com/yannick-thomas/breakglass-operator/internal/adapter/apiconv"
	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	"github.com/yannick-thomas/breakglass-operator/internal/usecase/expirysweep"
)

// New wires a sweeper to a Kubernetes client. The client must read directly
// from the API server: the guard must not act on a stale cache.
func New(c client.Client) *expirysweep.Sweeper {
	return &expirysweep.Sweeper{
		Sessions: sessionSource{Reader: c},
		Bindings: bindingGateway{Client: c},
		Grace:    expirysweep.DefaultGrace,
	}
}

type sessionSource struct {
	Reader client.Reader
}

func (s sessionSource) List(ctx context.Context) ([]access.Session, error) {
	var list accessv1alpha1.BreakGlassSessionList
	if err := s.Reader.List(ctx, &list); err != nil {
		return nil, err
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

// Delete removes the binding only if neither its UID nor its content changed
// since it was verified.
func (g bindingGateway) Delete(ctx context.Context, binding access.Binding) error {
	uid := types.UID(binding.UID)
	version := binding.Version
	obj := &rbacv1.RoleBinding{}
	obj.Namespace, obj.Name = binding.Namespace, binding.Name
	return apiconv.Classify(g.Client.Delete(ctx, obj, client.Preconditions{UID: &uid, ResourceVersion: &version}))
}
