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

package startup

import (
	"crypto/tls"
	"flag"
	"strings"
	"testing"

	"github.com/go-logr/logr"
)

const productionNamespace = "production"

func TestParseNamespaceFlag(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    map[string]struct{}
		wantErr string
	}{
		{name: "empty permits the development default", want: map[string]struct{}{}},
		{name: "one namespace", value: productionNamespace, want: map[string]struct{}{productionNamespace: {}}},
		{
			name:  "multiple namespaces ignore surrounding whitespace",
			value: productionNamespace + ", staging",
			want:  map[string]struct{}{productionNamespace: {}, "staging": {}},
		},
		{
			name:    "rejects empty item and names the flag",
			value:   "production,,staging",
			wantErr: "allowed-target-namespaces contains an empty namespace",
		},
		{name: "rejects invalid namespace", value: "Production", wantErr: "invalid namespace"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseNamespaceFlag(AllowedTargetNamespacesFlag, test.value)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("ParseNamespaceFlag(%q) error = %v, want substring %q", test.value, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseNamespaceFlag(%q) error = %v", test.value, err)
			}
			if len(got) != len(test.want) {
				t.Fatalf("ParseNamespaceFlag(%q) = %#v, want %#v", test.value, got, test.want)
			}
			for namespace := range test.want {
				if _, ok := got[namespace]; !ok {
					t.Fatalf("ParseNamespaceFlag(%q) = %#v, missing %q", test.value, got, namespace)
				}
			}
		})
	}
}

func TestPlacementFlags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "development default"},
		{name: "disjoint explicit scopes", args: []string{
			"--allowed-target-namespaces=production", "--control-namespaces=breakglass-access",
		}},
		{name: "names the control flag", args: []string{"--control-namespaces=Bad"}, wantErr: "control-namespaces"},
		{name: "rejects overlap", args: []string{
			"--allowed-target-namespaces=production", "--control-namespaces=production",
		}, wantErr: "production"},
		{name: "requires control with explicit targets", args: []string{
			"--allowed-target-namespaces=production",
		}, wantErr: "control"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs := flag.NewFlagSet("test", flag.ContinueOnError)
			var flags PlacementFlags
			flags.Bind(fs)
			if err := fs.Parse(test.args); err != nil {
				t.Fatal(err)
			}
			placement, err := flags.Placement()
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("Placement() error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Placement() error = %v", err)
			}
			if len(test.args) > 0 && (!placement.Target.Explicit() || !placement.Control.Explicit()) {
				t.Fatalf("Placement() = %#v, want explicit scopes", placement)
			}
		})
	}
}

func TestServingFlagsDefaultToSecureMetricsWithoutHTTP2(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var flags ServingFlags
	flags.Bind(fs)
	if err := fs.Parse([]string{"--metrics-bind-address=:8443"}); err != nil {
		t.Fatal(err)
	}
	tlsOpts := flags.TLSOptions(logr.Discard())
	if len(tlsOpts) != 1 {
		t.Fatalf("TLSOptions() returned %d options, want HTTP/2 disabled", len(tlsOpts))
	}
	config := &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	tlsOpts[0](config)
	if len(config.NextProtos) != 1 || config.NextProtos[0] != "http/1.1" {
		t.Fatalf("NextProtos = %v, want only http/1.1", config.NextProtos)
	}
	options := flags.MetricsOptions(logr.Discard(), tlsOpts)
	if !options.SecureServing || options.FilterProvider == nil || options.BindAddress != ":8443" {
		t.Fatalf("MetricsOptions() = %#v, want authenticated HTTPS on :8443", options)
	}
}
