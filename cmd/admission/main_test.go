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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// cacheReader fails the test if the admission client ever reads through a
// cache.
type cacheReader struct {
	t *testing.T
}

func (r cacheReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	r.t.Fatal("admission client read through the cache")
	return nil
}

func (r cacheReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	r.t.Fatal("admission client listed through the cache")
	return nil
}

func TestUncachedClientReadsFromTheAPIServer(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"production"}}`))
	}))
	defer server.Close()

	c, err := uncachedClient(&rest.Config{Host: server.URL}, client.Options{
		Scheme: scheme,
		Mapper: namespaceMapper(),
		Cache:  &client.CacheOptions{Reader: cacheReader{t: t}},
	})
	if err != nil {
		t.Fatalf("uncachedClient() error = %v", err)
	}
	if err := c.Get(context.Background(), client.ObjectKey{Name: "production"}, &corev1.Namespace{}); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if requests.Load() == 0 {
		t.Fatal("Get() did not reach the API server")
	}
}

func namespaceMapper() meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(schema.GroupVersionKind{Version: "v1", Kind: "Namespace"}, meta.RESTScopeRoot)
	return mapper
}
