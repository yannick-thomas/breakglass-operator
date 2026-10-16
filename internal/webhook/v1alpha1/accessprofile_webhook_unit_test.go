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

package v1alpha1

import (
	"context"
	"strings"
	"testing"

	"github.com/yannick-thomas/breakglass-operator/internal/domain/access"
	breakglassmetrics "github.com/yannick-thomas/breakglass-operator/internal/metrics"
)

func TestAccessProfileCreationIsLimitedToControlNamespaces(t *testing.T) {
	placement := access.Placement{
		Control: access.NamespaceScope{testControlNamespace: {}},
		Target:  access.NamespaceScope{"production": {}},
	}
	for name, tc := range map[string]struct {
		namespace, target string
		wantErr           string
	}{
		"control namespace":             {testControlNamespace, "production", ""},
		"target namespace":              {"production", "staging", "not in a control namespace"},
		"unrelated namespace":           {"team-b", "production", "not in a control namespace"},
		"grants in a control namespace": {testControlNamespace, testControlNamespace, "own namespace"},
		"target outside allowed set":    {testControlNamespace, "kube-system", "outside this manager's allowed namespace set"},
	} {
		t.Run(name, func(t *testing.T) {
			profile := testAccessProfile()
			profile.Namespace = tc.namespace
			profile.Spec.TargetNamespace = tc.target
			recorder := &recordingAdmissionRecorder{}
			validator := &AccessProfileValidator{Placement: placement, Metrics: recorder}

			_, err := validator.ValidateCreate(context.Background(), profile)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("ValidateCreate() error = %v, want admitted", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ValidateCreate() error = %v, want %q", err, tc.wantErr)
			}
			want := breakglassmetrics.AdmissionOutcomeAllowed
			if tc.wantErr != "" {
				want = breakglassmetrics.AdmissionOutcomeDenied
			}
			assertAdmissionDecisions(t, recorder, []admissionDecision{{operation: breakglassmetrics.AdmissionOperationCreate, outcome: want}})
		})
	}
}
