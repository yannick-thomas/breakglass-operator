//go:build e2e
// +build e2e

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

package production

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/yannick-thomas/breakglass-operator/test/utils"
)

const (
	managerImage     = "example.com/breakglass-operator:v0.0.1"
	managerName      = "breakglass-operator-controller-manager"
	managerNamespace = "breakglass-operator-system"
	targetNamespace  = "production"

	requesterName        = "production-e2e-requester"
	requesterRole        = "breakglass-production-e2e-requester"
	requesterRoleBinding = "breakglass-production-e2e-requester-binding"
	accessProfileName    = "production-pod-observer"
	curatedRoleName      = "breakglass-pod-observer"

	haSessionName                  = "production-ha-session"
	outageSessionName              = "production-webhook-outage-session"
	recoverySessionName            = "production-recovery-session"
	ruleDriftSessionName           = "production-role-drift-session"
	roleReuseSessionName           = "production-role-reuse-session"
	certificateRotationSessionName = "production-certificate-rotation-session"
	expiryRecoverySessionName      = "production-expiry-recovery-session"
)

var installedCertManager bool

func TestProductionE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "production e2e suite")
}

var _ = BeforeSuite(func() {
	By("building and loading the manager image into Kind with two schedulable workers")
	_, err := utils.Run(exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", managerImage)))
	Expect(err).NotTo(HaveOccurred())
	Expect(utils.LoadImageToKindClusterWithName(managerImage)).To(Succeed())

	if !utils.IsCertManagerCRDsInstalled() {
		installedCertManager = true
		Expect(utils.InstallCertManager()).To(Succeed())
	}
})

var _ = AfterSuite(func() {
	if installedCertManager {
		utils.UninstallCertManager()
	}
})

var _ = Describe("Production installation", Ordered, func() {
	BeforeAll(func() {
		By("installing CRDs and the high-availability production overlay")
		_, err := utils.Run(exec.Command("make", "install"))
		Expect(err).NotTo(HaveOccurred())
		_, err = utils.Run(exec.Command("make", "deploy-production", fmt.Sprintf("IMG=%s", managerImage)))
		Expect(err).NotTo(HaveOccurred())

		By("creating a namespaced curated profile and a least-privilege requester")
		_, err = utils.Run(exec.Command("kubectl", "create", "namespace", targetNamespace))
		Expect(err).NotTo(HaveOccurred())
		for _, path := range []string{
			"config/samples/rbac_breakglass_pod_observer_clusterrole.yaml",
			"config/samples/access_v1alpha1_accessprofile.yaml",
		} {
			_, err = utils.Run(exec.Command("kubectl", "apply", "-f", path))
			Expect(err).NotTo(HaveOccurred())
		}
		_, err = applyManifest(requesterRBAC)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		for _, session := range []string{
			haSessionName, outageSessionName, recoverySessionName, ruleDriftSessionName, roleReuseSessionName,
			certificateRotationSessionName, expiryRecoverySessionName,
		} {
			_, _ = utils.Run(exec.Command("kubectl", "delete", "breakglasssession", session, "--ignore-not-found"))
		}
		_, _ = utils.Run(exec.Command("kubectl", "delete", "clusterrolebinding", requesterRoleBinding, "--ignore-not-found"))
		_, _ = utils.Run(exec.Command(
			"kubectl", "delete", "clusterrole", requesterRole, curatedRoleName, "--ignore-not-found",
		))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "accessprofile", accessProfileName, "--ignore-not-found"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", targetNamespace, "--ignore-not-found"))
		_, _ = utils.Run(exec.Command("make", "undeploy-production"))
		_, _ = utils.Run(exec.Command("make", "uninstall"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", managerNamespace, "--ignore-not-found"))
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			_, _ = utils.Run(exec.Command("kubectl", "get", "pods", "-n", managerNamespace, "-o", "wide"))
			_, _ = utils.Run(exec.Command("kubectl", "get", "events", "-n", managerNamespace, "--sort-by=.lastTimestamp"))
		}
	})

	It("keeps the admission boundary safe through pod loss and total manager outage", func() {
		By("waiting for two ready managers, ready webhook endpoints, a ready certificate, and a PDB")
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())

		By("deleting one manager pod and waiting for HA recovery")
		pods := readyManagerPods()
		Expect(pods).To(HaveLen(2))
		_, err := utils.Run(exec.Command("kubectl", "delete", "pod", pods[0], "-n", managerNamespace))
		Expect(err).NotTo(HaveOccurred())
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())

		By("granting an attributed, namespaced session after the pod loss")
		Expect(createSession(haSessionName)).To(Succeed())
		Eventually(sessionIsActive(haSessionName), 2*time.Minute, time.Second).Should(Succeed())
		revokeSession(haSessionName)

		By("scaling every manager down without changing the fail-closed webhook configuration")
		_, err = utils.Run(exec.Command(
			"kubectl", "scale", "deployment", managerName, "-n", managerNamespace, "--replicas=0",
		))
		Expect(err).NotTo(HaveOccurred())
		Eventually(webhookEndpointsAreAbsent, 2*time.Minute, time.Second).Should(Succeed())

		By("proving that a new protected request is rejected while every webhook endpoint is unavailable")
		Expect(createSession(outageSessionName)).To(MatchError(ContainSubstring("failed")))

		By("restoring the manager deployment and proving that admission recovers")
		_, err = utils.Run(exec.Command(
			"kubectl", "scale", "deployment", managerName, "-n", managerNamespace, "--replicas=2",
		))
		Expect(err).NotTo(HaveOccurred())
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())
		Expect(createSession(recoverySessionName)).To(Succeed())
		Eventually(sessionIsActive(recoverySessionName), 2*time.Minute, time.Second).Should(Succeed())
		revokeSession(recoverySessionName)
	})

	It("suspends active sessions when the curated role changes or is recreated", func() {
		By("creating an active session with a snapshot of the curated role")
		Expect(createSession(ruleDriftSessionName)).To(Succeed())
		Eventually(sessionIsActive(ruleDriftSessionName), 2*time.Minute, time.Second).Should(Succeed())
		bindingName := sessionBindingName(ruleDriftSessionName)

		By("widening the curated role after the grant was created")
		_, err := utils.Run(exec.Command(
			"kubectl", "patch", "clusterrole", curatedRoleName, "--type=json",
			"-p", `[{"op":"add","path":"/rules/-","value":{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}}]`,
		))
		Expect(err).NotTo(HaveOccurred())
		Eventually(
			sessionIsSuspendedForCuratedRole(ruleDriftSessionName, "CuratedRoleRulesDrift"),
			2*time.Minute,
			time.Second,
		).Should(Succeed())
		Eventually(bindingIsDeleted(bindingName), time.Minute, time.Second).Should(Succeed())

		By("restoring the curated role before creating a fresh independently snapshotted session")
		resetCuratedRole()
		Expect(createSession(roleReuseSessionName)).To(Succeed())
		Eventually(sessionIsActive(roleReuseSessionName), 2*time.Minute, time.Second).Should(Succeed())
		bindingName = sessionBindingName(roleReuseSessionName)

		By("deleting and recreating the same curated role name")
		_, err = utils.Run(exec.Command("kubectl", "delete", "clusterrole", curatedRoleName))
		Expect(err).NotTo(HaveOccurred())
		resetCuratedRole()
		Eventually(
			sessionIsSuspendedForCuratedRole(roleReuseSessionName, "CuratedRoleUIDMismatch"),
			2*time.Minute,
			time.Second,
		).Should(Succeed())
		Eventually(bindingIsDeleted(bindingName), time.Minute, time.Second).Should(Succeed())
	})

	It("recovers webhook certificates and expires a grant after a complete manager restart", func() {
		By("forcing cert-manager to reissue the serving secret without weakening admission")
		previousCertificateSecretUID := certificateSecretUID()
		_, err := utils.Run(exec.Command("kubectl", "delete", "secret", "webhook-server-cert", "-n", managerNamespace))
		Expect(err).NotTo(HaveOccurred())
		Eventually(certificateSecretWasReissued(previousCertificateSecretUID), 5*time.Minute, time.Second).Should(Succeed())
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())
		Expect(createSession(certificateRotationSessionName)).To(Succeed())
		Eventually(sessionIsActive(certificateRotationSessionName), 2*time.Minute, time.Second).Should(Succeed())
		revokeSession(certificateRotationSessionName)

		By("allowing a session to pass its TTL while every manager is stopped")
		Expect(createSession(expiryRecoverySessionName)).To(Succeed())
		Eventually(sessionIsActive(expiryRecoverySessionName), 2*time.Minute, time.Second).Should(Succeed())
		bindingName := sessionBindingName(expiryRecoverySessionName)
		_, err = utils.Run(exec.Command("kubectl", "scale", "deployment", managerName, "-n", managerNamespace, "--replicas=0"))
		Expect(err).NotTo(HaveOccurred())
		Eventually(webhookEndpointsAreAbsent, 2*time.Minute, time.Second).Should(Succeed())
		Eventually(sessionHasPassedExpiry(expiryRecoverySessionName), 2*time.Minute, time.Second).Should(Succeed())
		_, err = utils.Run(exec.Command("kubectl", "scale", "deployment", managerName, "-n", managerNamespace, "--replicas=2"))
		Expect(err).NotTo(HaveOccurred())
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())
		Eventually(sessionHasPhase(expiryRecoverySessionName, "Expired"), 2*time.Minute, time.Second).Should(Succeed())
		Eventually(bindingIsDeleted(bindingName), time.Minute, time.Second).Should(Succeed())
	})
})

func assertProductionReady(g Gomega) {
	deployment, err := utils.Run(exec.Command(
		"kubectl", "get", "deployment", managerName, "-n", managerNamespace,
		"-o", "jsonpath={.spec.replicas},{.status.readyReplicas},{.status.availableReplicas}",
	))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(deployment).To(Equal("2,2,2"))
	g.Expect(readyManagerPods()).To(HaveLen(2))

	pdb, err := utils.Run(exec.Command(
		"kubectl", "get", "pdb", managerName, "-n", managerNamespace,
		"-o", "jsonpath={.spec.minAvailable}",
	))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(pdb).To(Equal("1"))

	certificate, err := utils.Run(exec.Command(
		"kubectl", "get", "certificate", "breakglass-operator-serving-cert", "-n", managerNamespace,
		"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}",
	))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(certificate).To(Equal("True"))

	endpoints, err := readyWebhookEndpointCount()
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(endpoints).To(Equal(2))
}

func readyManagerPods() []string {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "pods", "-n", managerNamespace,
		"-l", "control-plane=controller-manager",
		"-o", "jsonpath={range .items[?(@.status.phase=='Running')]}{.metadata.name}{'\\n'}{end}",
	))
	Expect(err).NotTo(HaveOccurred())
	return utils.GetNonEmptyLines(output)
}

func readyWebhookEndpointCount() (int, error) {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "endpointslices.discovery.k8s.io", "-n", managerNamespace,
		"-l", "kubernetes.io/service-name=breakglass-operator-webhook-service",
		"-o", "jsonpath={range .items[*].endpoints[?(@.conditions.ready==true)]}{.addresses[0]}{'\\n'}{end}",
	))
	if err != nil {
		return 0, err
	}
	return len(utils.GetNonEmptyLines(output)), nil
}

func webhookEndpointsAreAbsent(g Gomega) {
	count, err := readyWebhookEndpointCount()
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(count).To(BeZero())
}

func certificateSecretUID() string {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "secret", "webhook-server-cert", "-n", managerNamespace, "-o", "jsonpath={.metadata.uid}",
	))
	Expect(err).NotTo(HaveOccurred())
	Expect(output).NotTo(BeEmpty())
	return output
}

func certificateSecretWasReissued(previousUID string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command(
			"kubectl", "get", "secret", "webhook-server-cert", "-n", managerNamespace, "-o", "jsonpath={.metadata.uid}",
		))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).NotTo(Equal(previousUID))
	}
}

func createSession(name string) error {
	_, err := applyManifestAs(requesterName, fmt.Sprintf(`
apiVersion: access.breakglass.io/v1alpha1
kind: BreakGlassSession
metadata:
  name: %s
spec:
  accessProfile: %s
  duration: "1m"
  reason: "Production HA and fail-closed admission verification"
`, name, accessProfileName))
	return err
}

func sessionIsActive(name string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command(
			"kubectl", "--as="+requesterName, "get", "breakglasssession", name,
			"-o", "jsonpath={.status.phase},{.spec.subject.name},{.status.bindingRef.name}",
		))
		g.Expect(err).NotTo(HaveOccurred())
		parts := strings.Split(output, ",")
		g.Expect(parts).To(HaveLen(3))
		g.Expect(parts[0]).To(Equal("Active"))
		g.Expect(parts[1]).To(Equal(requesterName))
		g.Expect(parts[2]).NotTo(BeEmpty())
	}
}

func sessionHasPhase(name, phase string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command("kubectl", "get", "breakglasssession", name, "-o", "jsonpath={.status.phase}"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal(phase))
	}
}

func sessionHasPassedExpiry(name string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command("kubectl", "get", "breakglasssession", name, "-o", "jsonpath={.status.expiresAt}"))
		g.Expect(err).NotTo(HaveOccurred())
		expiresAt, err := time.Parse(time.RFC3339, output)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(time.Now()).To(BeTemporally(">", expiresAt))
	}
}

func sessionBindingName(name string) string {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "breakglasssession", name, "-o", "jsonpath={.status.bindingRef.name}",
	))
	Expect(err).NotTo(HaveOccurred())
	Expect(output).NotTo(BeEmpty())
	return output
}

func sessionIsSuspendedForCuratedRole(name, reason string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command(
			"kubectl", "get", "breakglasssession", name,
			"-o", "jsonpath={.status.phase},{.status.conditions[?(@.type=='CuratedRoleValid')].reason}",
		))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("Suspended," + reason))
	}
}

func bindingIsDeleted(name string) func(Gomega) {
	return func(g Gomega) {
		_, err := utils.Run(exec.Command("kubectl", "get", "rolebinding", name, "-n", targetNamespace))
		g.Expect(err).To(HaveOccurred())
	}
}

func resetCuratedRole() {
	_, err := utils.Run(exec.Command(
		"kubectl", "apply", "-f", "config/samples/rbac_breakglass_pod_observer_clusterrole.yaml",
	))
	Expect(err).NotTo(HaveOccurred())
}

func revokeSession(name string) {
	_, err := utils.Run(exec.Command(
		"kubectl", "patch", "breakglasssession", name, "--type=merge", "-p", `{"spec":{"revoked":true}}`,
	))
	Expect(err).NotTo(HaveOccurred())
	Eventually(func(g Gomega) {
		output, err := utils.Run(exec.Command("kubectl", "get", "breakglasssession", name, "-o", "jsonpath={.status.phase}"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("Revoked"))
	}, 2*time.Minute, time.Second).Should(Succeed())
}

func applyManifest(manifest string) (string, error) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	return utils.Run(cmd)
}

func applyManifestAs(user, manifest string) (string, error) {
	cmd := exec.Command("kubectl", "--as="+user, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	return utils.Run(cmd)
}

const requesterRBAC = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-production-e2e-requester
rules:
  - apiGroups: ["access.breakglass.io"]
    resources: ["breakglasssessions"]
    verbs: ["create", "get", "list", "watch"]
  - apiGroups: ["access.breakglass.io"]
    resources: ["accessprofiles"]
    resourceNames: ["production-pod-observer"]
    verbs: ["use"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-production-e2e-requester-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-production-e2e-requester
subjects:
  - kind: User
    name: production-e2e-requester
    apiGroup: rbac.authorization.k8s.io
`
