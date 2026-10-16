// Copyright 2026.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// admissionFixture is the smallest default-profile object set that satisfies
// verifyAdmission.
const managerIdentity = "system:serviceaccount:breakglass-operator-system:breakglass-operator-controller-manager"

var admissionFixture = strings.ReplaceAll(`
apiVersion: apps/v1
kind: Deployment
metadata: {name: breakglass-operator-admission, namespace: breakglass-operator-system}
spec:
  template:
    metadata:
      labels: {app.kubernetes.io/name: breakglass-operator, app.kubernetes.io/component: admission}
    spec:
      serviceAccountName: breakglass-operator-admission
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
      - name: admission
        command: [/admission]
        args:
        - --metrics-bind-address=:8443
        - --webhook-port=9443
        - --webhook-cert-path=/certs
        - --request-controller-username=MANAGER_IDENTITY
        ports: [{containerPort: 9443}]
        volumeMounts: [{name: webhook-certs, mountPath: /certs}]
        securityContext: {readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumes: [{name: webhook-certs, secret: {secretName: webhook-server-cert}}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: breakglass-operator-controller-manager, namespace: breakglass-operator-system}
spec:
  template:
    metadata:
      labels: {app.kubernetes.io/name: breakglass-operator, control-plane: controller-manager}
    spec:
      serviceAccountName: breakglass-operator-controller-manager
      containers:
      - name: manager
        args:
        - --leader-elect
        - --request-controller-username=MANAGER_IDENTITY
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: breakglass-operator-serving-cert, namespace: breakglass-operator-system}
spec: {secretName: webhook-server-cert}
---
apiVersion: v1
kind: Service
metadata: {name: breakglass-operator-webhook-service, namespace: breakglass-operator-system}
spec:
  selector: {app.kubernetes.io/name: breakglass-operator, app.kubernetes.io/component: admission}
  ports: [{port: 443, targetPort: 9443}]
---
apiVersion: v1
kind: Service
metadata: {name: breakglass-operator-admission-metrics-service, namespace: breakglass-operator-system}
spec:
  selector: {app.kubernetes.io/component: admission}
---
apiVersion: v1
kind: ServiceAccount
metadata: {name: breakglass-operator-admission, namespace: breakglass-operator-system}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: breakglass-operator-admission-role}
rules:
- {apiGroups: [""], resources: [namespaces], verbs: [get]}
- apiGroups: [access.breakglass.io]
  resources: [accessprofiles, breakglassapprovals, breakglassrequests, breakglasssessions]
  verbs: [get, list]
- {apiGroups: [authorization.k8s.io], resources: [subjectaccessreviews], verbs: [create]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: breakglass-operator-admission-rolebinding}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: breakglass-operator-admission-role}
subjects:
- {kind: ServiceAccount, name: breakglass-operator-admission, namespace: breakglass-operator-system}
`, "MANAGER_IDENTITY", managerIdentity)

const sarRule = "- {apiGroups: [authorization.k8s.io]"

func TestVerifyAdmissionAcceptsFixture(t *testing.T) {
	if err := verifyAdmission(admissionObjects(t, admissionFixture), defaultProfile); err != nil {
		t.Fatalf("verifyAdmission() error = %v", err)
	}
}

func TestVerifyAdmissionRejects(t *testing.T) {
	for _, tc := range []struct {
		name    string
		old     string
		new     string
		wantErr string
	}{
		{
			name:    "manager identity",
			old:     "serviceAccountName: breakglass-operator-admission",
			new:     "serviceAccountName: breakglass-operator-controller-manager",
			wantErr: "own ServiceAccount",
		},
		{
			name:    "webhook Service selecting the manager",
			old:     "selector: {app.kubernetes.io/name: breakglass-operator, app.kubernetes.io/component: admission}",
			new:     "selector: {app.kubernetes.io/name: breakglass-operator}",
			wantErr: "must not select the manager",
		},
		{
			name:    "webhook port on the manager",
			old:     "        - --leader-elect\n",
			new:     "        - --leader-elect\n        - --webhook-port=9443\n",
			wantErr: "manager must not expose a webhook",
		},
		{
			name:    "different placement",
			old:     "        - --leader-elect\n",
			new:     "        - --leader-elect\n        - --control-namespaces=breakglass-access\n",
			wantErr: "identical --control-namespaces",
		},
		{
			name:    "trusting another identity",
			old:     "        - --request-controller-username=" + managerIdentity + "\n        ports",
			new:     "        - --request-controller-username=system:serviceaccount:other:other\n        ports",
			wantErr: "trust exactly the manager",
		},
		{
			name:    "session writes",
			old:     "  verbs: [get, list]",
			new:     "  verbs: [get, list, update]",
			wantErr: "forbidden rule",
		},
		{
			name:    "RoleBinding access",
			old:     sarRule,
			new:     "- {apiGroups: [rbac.authorization.k8s.io], resources: [rolebindings], verbs: [get]}\n" + sarRule,
			wantErr: "forbidden rule",
		},
		{
			name:    "bind",
			old:     sarRule,
			new:     "- {apiGroups: [rbac.authorization.k8s.io], resources: [clusterroles], verbs: [bind]}\n" + sarRule,
			wantErr: "forbidden rule",
		},
		{
			name:    "status writes",
			old:     "resources: [accessprofiles, breakglassapprovals",
			new:     "resources: [accessprofiles/status, accessprofiles, breakglassapprovals",
			wantErr: "forbidden rule",
		},
		{
			name:    "missing SubjectAccessReview create",
			old:     "- {apiGroups: [authorization.k8s.io], resources: [subjectaccessreviews], verbs: [create]}",
			new:     "",
			wantErr: "SubjectAccessReviews",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(admissionFixture, tc.old) {
				t.Fatalf("fixture does not contain %q", tc.old)
			}
			objects := admissionObjects(t, strings.Replace(admissionFixture, tc.old, tc.new, 1))
			err := verifyAdmission(objects, defaultProfile)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("verifyAdmission() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func admissionObjects(t *testing.T, manifest string) []unstructured.Unstructured {
	t.Helper()
	objects, err := decodeObjects(strings.NewReader(manifest))
	if err != nil {
		t.Fatal(err)
	}
	return objects
}
