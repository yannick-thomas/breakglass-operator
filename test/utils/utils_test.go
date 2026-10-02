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

package utils

import "testing"

func TestConfiguredCertManagerVersion(t *testing.T) {
	t.Run("uses the pinned default when no override is supplied", func(t *testing.T) {
		t.Setenv("CERT_MANAGER_VERSION", "")
		if got := configuredCertManagerVersion(); got != defaultCertManagerVersion {
			t.Fatalf("configuredCertManagerVersion() = %q, want %q", got, defaultCertManagerVersion)
		}
	})

	t.Run("uses a non-empty explicit qualification override", func(t *testing.T) {
		t.Setenv("CERT_MANAGER_VERSION", " v1.21.1 ")
		if got := configuredCertManagerVersion(); got != "v1.21.1" {
			t.Fatalf("configuredCertManagerVersion() = %q, want v1.21.1", got)
		}
	})
}
