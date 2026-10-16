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
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/yannick-thomas/breakglass-operator/test/utils"
)

const (
	managerImage = "example.com/breakglass-operator:v0.0.1"
	managerName  = "breakglass-operator-controller-manager"
	// admissionName is the separate Deployment, PDB and ServiceAccount that
	// serves every webhook (ADR-005); both installers use this name.
	admissionName     = "breakglass-operator-admission"
	managerSelector   = "control-plane=controller-manager"
	admissionSelector = "app.kubernetes.io/component=admission"
	managerNamespace  = "breakglass-operator-system"
	targetNamespace   = "production"
	// controlNamespace holds the access objects (ADR-004); it matches the
	// production overlay and the chart default.
	controlNamespace = "breakglass-access"
	// teardownNamespace is a second control namespace, installed only through
	// Helm, that the drain-check spec deletes (ADR-004).
	teardownNamespace = "breakglass-teardown"

	requesterName        = "production-e2e-requester"
	requesterRole        = "breakglass-production-e2e-requester"
	requesterRoleBinding = "breakglass-production-e2e-requester-binding"
	accessProfileName    = "production-pod-observer"
	curatedRoleName      = "breakglass-pod-observer"

	haSessionName                  = "production-ha-session"
	outageSessionName              = "production-webhook-outage-session"
	managerOutageSessionName       = "production-manager-outage-session"
	recoverySessionName            = "production-recovery-session"
	ruleDriftSessionName           = "production-role-drift-session"
	roleReuseSessionName           = "production-role-reuse-session"
	certificateRotationSessionName = "production-certificate-rotation-session"
	expiryRecoverySessionName      = "production-expiry-recovery-session"
	rollingRestartSessionName      = "production-rolling-restart-session"
	rollingRestartRecoverySession  = "production-rolling-restart-recovery-session"
	namespaceDeletionSessionName   = "production-namespace-deletion-session"
	expiryGuardSessionName         = "production-expiry-guard-session"
	teardownSessionName            = "production-teardown-session"

	expiryGuardName = "breakglass-operator-expiry-guard"
)

var installedCertManager bool

func usesHelm() bool {
	return os.Getenv("PRODUCTION_INSTALLER") == "helm"
}

func helmInstallCommand(upgrade bool) *exec.Cmd {
	helm := os.Getenv("HELM")
	if helm == "" {
		helm = "helm"
	}
	args := []string{"upgrade", "--install", "breakglass-operator", "charts/breakglass-operator",
		"--namespace", managerNamespace, "--create-namespace", "--wait", "--timeout", "5m",
		"--set", "image.repository=example.com/breakglass-operator", "--set", "image.tag=v0.0.1",
		"--set", "controlNamespaces={" + controlNamespace + "," + teardownNamespace + "}"}
	if upgrade {
		args = append(args, "--set", "resources.requests.cpu=15m")
	}
	return exec.Command(helm, args...)
}

func webhookSecretName() string {
	if usesHelm() {
		return "breakglass-operator-webhook-server-cert"
	}
	return "webhook-server-cert"
}

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
		By("creating the target and control namespaces before installing the namespaced production overlay")
		_, err := utils.Run(exec.Command("kubectl", "create", "namespace", targetNamespace))
		Expect(err).NotTo(HaveOccurred())
		_, err = utils.Run(exec.Command("kubectl", "create", "namespace", controlNamespace))
		Expect(err).NotTo(HaveOccurred())
		if usesHelm() {
			By("creating a second control namespace that the drain-check spec retires")
			_, err = utils.Run(exec.Command("kubectl", "create", "namespace", teardownNamespace))
			Expect(err).NotTo(HaveOccurred())
			By("installing the chart with CRDs and namespace-restricted high-availability RBAC")
			_, err = utils.Run(helmInstallCommand(false))
			Expect(err).NotTo(HaveOccurred())
		} else {
			By("installing CRDs and the high-availability namespaced production overlay")
			_, err = utils.Run(exec.Command("make", "install"))
			Expect(err).NotTo(HaveOccurred())
			_, err = utils.Run(exec.Command("make", "deploy-production",
				"PRODUCTION_OVERLAY=production-namespaced", fmt.Sprintf("IMG=%s", managerImage)))
			Expect(err).NotTo(HaveOccurred())
		}

		By("waiting until the manager and the separate admission Deployment are available")
		for _, name := range []string{managerName, admissionName} {
			_, err = utils.Run(exec.Command(
				"kubectl", "wait", "--for=condition=Available", "deployment/"+name,
				"-n", managerNamespace, "--timeout=5m",
			))
			Expect(err).NotTo(HaveOccurred())
		}

		By("creating a namespaced curated profile and a least-privilege requester")
		// Profiles pass admission (ADR-004), which fails closed: retry until
		// the webhook Service routes to the just-started admission pods.
		for _, path := range []string{
			"config/samples/rbac_breakglass_pod_observer_clusterrole.yaml",
			"config/samples/access_v1alpha1_accessprofile.yaml",
		} {
			Eventually(func() error {
				_, applyErr := utils.Run(exec.Command("kubectl", "apply", "-f", path))
				return applyErr
			}, 2*time.Minute, 2*time.Second).Should(Succeed())
		}
		_, err = applyManifest(requesterRBAC)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterAll(func() {
		// A failed outage assertion can leave the manager or admission scaled to
		// zero. Ask for recovery before deleting sessions so their finalizers have
		// a controller and their updates an admission server; the deletes below
		// are still non-blocking as a final guard.
		for _, name := range []string{managerName, admissionName} {
			_, _ = utils.Run(exec.Command(
				"kubectl", "scale", "deployment", name, "-n", managerNamespace, "--replicas=2",
			))
		}
		for _, session := range []string{
			haSessionName, outageSessionName, managerOutageSessionName, recoverySessionName,
			ruleDriftSessionName, roleReuseSessionName,
			certificateRotationSessionName, expiryRecoverySessionName, rollingRestartSessionName,
			rollingRestartRecoverySession, namespaceDeletionSessionName, expiryGuardSessionName,
		} {
			_, _ = utils.Run(exec.Command(
				"kubectl", "-n", controlNamespace, "delete", "breakglasssession", session, "--ignore-not-found", "--wait=false",
			))
		}
		_, _ = utils.Run(exec.Command(
			"kubectl", "-n", teardownNamespace, "delete", "breakglasssession", teardownSessionName,
			"--ignore-not-found", "--wait=false",
		))
		// Control namespaces may be deleted only after their sessions are gone
		// (ADR-004); give the restored manager time to release the finalizers.
		for _, namespace := range []string{controlNamespace, teardownNamespace} {
			waitForNoSessions(namespace)
		}
		_, _ = utils.Run(exec.Command("kubectl", "delete", "rolebinding", requesterRoleBinding, "-n", controlNamespace, "--ignore-not-found"))
		_, _ = utils.Run(exec.Command(
			"kubectl", "delete", "clusterrole", requesterRole, curatedRoleName, "--ignore-not-found",
		))
		_, _ = utils.Run(exec.Command("kubectl", "-n", controlNamespace, "delete", "accessprofile", accessProfileName, "--ignore-not-found"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", targetNamespace, controlNamespace,
			teardownNamespace, "--ignore-not-found"))
		if usesHelm() {
			helm := os.Getenv("HELM")
			if helm == "" {
				helm = "helm"
			}
			_, _ = utils.Run(exec.Command(helm, "uninstall", "breakglass-operator", "-n", managerNamespace))
		} else {
			_, _ = utils.Run(exec.Command("make", "undeploy-production-test", "PRODUCTION_OVERLAY=production-namespaced"))
		}
		_, _ = utils.Run(exec.Command("make", "uninstall-test"))
		_, _ = utils.Run(exec.Command("kubectl", "delete", "namespace", managerNamespace, "--ignore-not-found"))
	})

	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			reportProductionDiagnostics()
		}
	})

	It("keeps the admission boundary safe through pod loss and total admission outage", func() {
		By("waiting for two ready managers, two ready admission webhook endpoints, a ready certificate, and PDBs")
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())

		By("verifying that admission runs under its own least-privilege identity")
		verifyAdmissionIdentity()

		By("deleting one manager pod and one admission pod and waiting for HA recovery")
		for _, selector := range []string{managerSelector, admissionSelector} {
			pods := readyPods(selector)
			Expect(pods).To(HaveLen(2))
			_, err := utils.Run(exec.Command("kubectl", "delete", "pod", pods[0], "-n", managerNamespace))
			Expect(err).NotTo(HaveOccurred())
		}
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())

		By("granting an attributed, namespaced session after the pod loss")
		Expect(createSession(haSessionName)).To(Succeed())
		Eventually(sessionIsActive(haSessionName), 2*time.Minute, time.Second).Should(Succeed())
		revokeSession(haSessionName)

		By("scaling every admission pod down without changing the fail-closed webhook configuration")
		scaleDeployment(admissionName, 0)
		DeferCleanup(restoreDeployment, admissionName)
		Eventually(deploymentIsStopped(admissionName, admissionSelector), 2*time.Minute, time.Second).Should(Succeed())

		By("proving that a new protected request is rejected while admission is unavailable")
		Expect(createSession(outageSessionName)).To(MatchError(ContainSubstring("failed calling webhook")))

		By("restoring the admission deployment and proving that admission recovers")
		scaleDeployment(admissionName, 2)
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())
		Eventually(func() error {
			return createSession(recoverySessionName)
		}, 2*time.Minute, time.Second).Should(Succeed())
		Eventually(sessionIsActive(recoverySessionName), 2*time.Minute, time.Second).Should(Succeed())
		revokeSession(recoverySessionName)

		By("stopping every manager while admission stays available")
		scaleDeployment(managerName, 0)
		DeferCleanup(restoreDeployment, managerName)
		Eventually(deploymentIsStopped(managerName, managerSelector), 2*time.Minute, time.Second).Should(Succeed())

		By("proving that a manager outage does not block admission, only provisioning")
		Expect(createSession(managerOutageSessionName)).To(Succeed())
		Expect(sessionPhase(managerOutageSessionName)).NotTo(Equal("Active"),
			"no controller may have provisioned the session during the manager outage")

		By("restoring the managers and requiring the admitted session to be provisioned")
		scaleDeployment(managerName, 2)
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())
		Eventually(sessionIsActive(managerOutageSessionName), 2*time.Minute, time.Second).Should(Succeed())
		revokeSession(managerOutageSessionName)
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

	It("retains an active grant through a rolling manager restart", func() {
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())

		By("creating a non-expiring-during-test namespaced session")
		Expect(createSessionWithDuration(rollingRestartSessionName, "5m")).To(Succeed())
		Eventually(sessionIsActive(rollingRestartSessionName), 2*time.Minute, time.Second).Should(Succeed())
		bindingName, bindingUID := sessionBindingReference(rollingRestartSessionName)
		Expect(roleBindingUID(bindingName)).To(Equal(bindingUID))

		if usesHelm() {
			By("upgrading the Helm release, which rolls the manager and admission, without changing the active grant")
			previousUIDs := append(podUIDs(managerSelector), podUIDs(admissionSelector)...)
			Expect(previousUIDs).To(HaveLen(4))
			_, err := utils.Run(helmInstallCommand(true))
			Expect(err).NotTo(HaveOccurred())
			Eventually(func(g Gomega) {
				assertProductionReady(g)
				for _, selector := range []string{managerSelector, admissionSelector} {
					current := podUIDs(selector)
					g.Expect(current).To(HaveLen(2))
					for _, previousUID := range previousUIDs {
						g.Expect(current).NotTo(ContainElement(previousUID))
					}
				}
			}, 5*time.Minute, time.Second).Should(Succeed())
			Eventually(sessionIsActive(rollingRestartSessionName), 2*time.Minute, time.Second).Should(Succeed())
			currentBindingName, currentBindingUID := sessionBindingReference(rollingRestartSessionName)
			Expect(currentBindingName).To(Equal(bindingName))
			Expect(currentBindingUID).To(Equal(bindingUID))
		}

		By("restarting only the manager deployment without changing the active grant")
		previousManagerUIDs := podUIDs(managerSelector)
		Expect(previousManagerUIDs).To(HaveLen(2))
		admissionUIDs := podUIDs(admissionSelector)
		Expect(admissionUIDs).To(HaveLen(2))
		_, err := utils.Run(exec.Command(
			"kubectl", "rollout", "restart", "deployment", managerName, "-n", managerNamespace,
		))
		Expect(err).NotTo(HaveOccurred())

		By("admitting a new least-privilege request while the manager rollout is still in progress")
		// Admission runs separately (ADR-005): a manager rollout must not
		// remove a single webhook endpoint, so no retry is allowed here.
		Expect(createSession(rollingRestartRecoverySession)).To(Succeed())

		Eventually(func(g Gomega) {
			assertProductionReady(g)
			currentManagerUIDs := podUIDs(managerSelector)
			g.Expect(currentManagerUIDs).To(HaveLen(2))
			for _, previousUID := range previousManagerUIDs {
				g.Expect(currentManagerUIDs).NotTo(ContainElement(previousUID))
			}
		}, 5*time.Minute, time.Second).Should(Succeed())
		Expect(podUIDs(admissionSelector)).To(ConsistOf(admissionUIDs),
			"a manager rollout must not restart the admission pods")

		By("requiring the exact session and RoleBinding identity to remain unchanged")
		Eventually(sessionIsActive(rollingRestartSessionName), 2*time.Minute, time.Second).Should(Succeed())
		currentBindingName, currentBindingUID := sessionBindingReference(rollingRestartSessionName)
		Expect(currentBindingName).To(Equal(bindingName))
		Expect(currentBindingUID).To(Equal(bindingUID))
		Expect(roleBindingUID(bindingName)).To(Equal(bindingUID))

		By("requiring the request admitted during the rollout to be provisioned")
		Eventually(sessionIsActive(rollingRestartRecoverySession), 2*time.Minute, time.Second).Should(Succeed())
		revokeSession(rollingRestartRecoverySession)
		revokeSession(rollingRestartSessionName)
	})

	It("recovers webhook certificates and expires a grant after a complete manager restart", func() {
		By("forcing cert-manager to reissue the serving secret without weakening admission")
		previousCertificateSecretUID := certificateSecretUID()
		_, err := utils.Run(exec.Command("kubectl", "delete", "secret", webhookSecretName(), "-n", managerNamespace))
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
		scaleDeployment(managerName, 0)
		DeferCleanup(restoreDeployment, managerName)
		Eventually(managerIsStopped, 2*time.Minute, time.Second).Should(Succeed())
		Eventually(sessionHasPassedExpiry(expiryRecoverySessionName), 2*time.Minute, time.Second).Should(Succeed())
		scaleDeployment(managerName, 2)
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())
		Eventually(sessionHasPhase(expiryRecoverySessionName, "Expired"), 2*time.Minute, time.Second).Should(Succeed())
		Eventually(bindingIsDeleted(bindingName), time.Minute, time.Second).Should(Succeed())
	})

	It("removes an expired grant through the independent expiry guard while every manager is stopped", func() {
		By("verifying that the guard runs with its own identity, not the manager's")
		serviceAccount, err := utils.Run(exec.Command(
			"kubectl", "get", "cronjob", expiryGuardName, "-n", managerNamespace,
			"-o", "jsonpath={.spec.jobTemplate.spec.template.spec.serviceAccountName}",
		))
		Expect(err).NotTo(HaveOccurred())
		Expect(serviceAccount).To(Equal(expiryGuardName))

		By("activating a short grant and stopping every manager before it expires")
		Expect(createSession(expiryGuardSessionName)).To(Succeed())
		Eventually(sessionIsActive(expiryGuardSessionName), 2*time.Minute, time.Second).Should(Succeed())
		bindingName, bindingUID := sessionBindingReference(expiryGuardSessionName)
		Expect(roleBindingUID(bindingName)).To(Equal(bindingUID))
		scaleDeployment(managerName, 0)
		DeferCleanup(restoreDeployment, managerName)
		Eventually(managerIsStopped, 2*time.Minute, time.Second).Should(Succeed())

		By("requiring the guard to delete exactly the recorded binding without any manager")
		// Expiry, the two-minute grace period, the one-minute schedule, and
		// Job start-up bound this wait.
		Eventually(bindingIsDeleted(bindingName), 6*time.Minute, 5*time.Second).Should(Succeed())
		Expect(managerIsStopped()).To(Succeed(), "the binding must have been removed while no manager ran")
		phase, err := utils.Run(exec.Command(
			"kubectl", "-n", controlNamespace, "get", "breakglasssession", expiryGuardSessionName, "-o", "jsonpath={.status.phase}",
		))
		Expect(err).NotTo(HaveOccurred())
		Expect(phase).To(Equal("Active"), "no controller may have processed the expiry yet")
		Eventually(expiryGuardRemovedBinding(bindingName), time.Minute, 5*time.Second).Should(Succeed())

		By("restoring the managers and requiring a clean expiry without a drift incident")
		scaleDeployment(managerName, 2)
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())
		Eventually(func(g Gomega) {
			output, err := utils.Run(exec.Command(
				"kubectl", "-n", controlNamespace, "get", "breakglasssession", expiryGuardSessionName,
				"-o", "jsonpath={.status.phase},{.status.conditions[?(@.type=='BindingIntegrity')].reason}",
			))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(output).To(Equal("Expired,BindingAlreadyRemoved"))
		}, 2*time.Minute, time.Second).Should(Succeed())
	})

	It("denies retiring a control namespace until its sessions are drained, also during outages", func() {
		if !usesHelm() {
			Skip("the second control namespace is configured only by the Helm installation")
		}
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())

		By("creating a profile, requester access and an active session in a second control namespace")
		_, err := applyManifest(teardownAccess)
		Expect(err).NotTo(HaveOccurred())
		Expect(createSessionIn(teardownNamespace, teardownSessionName, "10m")).To(Succeed())
		Eventually(sessionIsActiveIn(teardownNamespace, teardownSessionName), 2*time.Minute, time.Second).
			Should(Succeed())
		bindingName, err := utils.Run(exec.Command(
			"kubectl", "-n", teardownNamespace, "get", "breakglasssession", teardownSessionName,
			"-o", "jsonpath={.status.bindingRef.name}",
		))
		Expect(err).NotTo(HaveOccurred())
		Expect(bindingName).NotTo(BeEmpty())

		By("stopping every manager while admission stays available")
		scaleDeployment(managerName, 0)
		DeferCleanup(restoreDeployment, managerName)
		Eventually(managerIsStopped, 2*time.Minute, time.Second).Should(Succeed())

		By("proving that admission alone still denies the deletion while a session exists")
		requireDrainDenial()

		By("stopping every admission pod as well")
		scaleDeployment(admissionName, 0)
		DeferCleanup(restoreDeployment, admissionName)
		Eventually(deploymentIsStopped(admissionName, admissionSelector), 2*time.Minute, time.Second).Should(Succeed())

		By("proving that the fail-closed drain check denies the deletion while admission is unavailable")
		output, err := utils.Run(exec.Command("kubectl", "delete", "namespace", teardownNamespace, "--wait=false"))
		Expect(err).To(HaveOccurred(), "namespace deletion was admitted during the admission outage: %s", output)
		Expect(err.Error()).To(ContainSubstring("failed calling webhook"))
		Expect(err.Error()).To(ContainSubstring("vcontrolnamespace-v1.kb.io"))
		Expect(namespacePhase(teardownNamespace)).To(Equal("Active"))
		_, err = utils.Run(exec.Command("kubectl", "-n", teardownNamespace, "get", "breakglasssession", teardownSessionName))
		Expect(err).NotTo(HaveOccurred())

		By("restoring admission and the managers")
		scaleDeployment(admissionName, 2)
		scaleDeployment(managerName, 2)
		Eventually(assertProductionReady, 5*time.Minute, time.Second).Should(Succeed())

		By("proving that the restored installation still denies the deletion while a session exists")
		requireDrainDenial()

		By("draining the session and waiting until the manager removed its RoleBinding")
		_, err = utils.Run(exec.Command(
			"kubectl", "-n", teardownNamespace, "delete", "breakglasssession", teardownSessionName, "--wait=false",
		))
		Expect(err).NotTo(HaveOccurred())
		Eventually(func(g Gomega) {
			_, getErr := utils.Run(exec.Command(
				"kubectl", "-n", teardownNamespace, "get", "breakglasssession", teardownSessionName))
			g.Expect(getErr).To(HaveOccurred())
		}, 2*time.Minute, time.Second).Should(Succeed())
		Eventually(bindingIsDeleted(bindingName), 2*time.Minute, time.Second).Should(Succeed())

		By("deleting the drained control namespace")
		_, err = utils.Run(exec.Command("kubectl", "delete", "namespace", teardownNamespace, "--wait=false"))
		Expect(err).NotTo(HaveOccurred())
		Eventually(namespaceIsDeleted(teardownNamespace), 2*time.Minute, time.Second).Should(Succeed())
	})

	It("releases the session finalizer when its target namespace disappears", func() {
		By("creating a final active grant before deleting its target namespace")
		Expect(createSessionWithDuration(namespaceDeletionSessionName, "5m")).To(Succeed())
		Eventually(sessionIsActive(namespaceDeletionSessionName), 2*time.Minute, time.Second).Should(Succeed())

		By("removing the manager's namespace permissions before namespace and session cleanup")
		_, err := utils.Run(exec.Command("kubectl", "delete", "rolebinding",
			"breakglass-operator-manager-rolebindings", "-n", targetNamespace))
		Expect(err).NotTo(HaveOccurred())
		Eventually(func(g Gomega) {
			output, checkErr := utils.Run(exec.Command("kubectl",
				"--as=system:serviceaccount:"+managerNamespace+":"+managerName,
				"auth", "can-i", "delete", "rolebindings", "-n", targetNamespace))
			g.Expect(checkErr).To(HaveOccurred())
			g.Expect(strings.TrimSpace(output)).To(Equal("no"))
		}, time.Minute, time.Second).Should(Succeed())

		By("deleting the namespace and session without relying on RoleBinding delete ordering")
		_, err = utils.Run(exec.Command("kubectl", "delete", "namespace", targetNamespace, "--wait=false"))
		Expect(err).NotTo(HaveOccurred())
		_, err = utils.Run(exec.Command(
			"kubectl", "-n", controlNamespace, "delete", "breakglasssession", namespaceDeletionSessionName, "--wait=false",
		))
		Expect(err).NotTo(HaveOccurred())

		By("requiring finalizer completion even after Kubernetes has removed the RoleBinding")
		Eventually(sessionIsDeleted(namespaceDeletionSessionName), 2*time.Minute, time.Second).Should(Succeed())
		Eventually(namespaceIsDeleted(targetNamespace), 2*time.Minute, time.Second).Should(Succeed())
	})
})

func assertProductionReady(g Gomega) {
	for _, component := range []struct{ name, selector string }{
		{managerName, managerSelector}, {admissionName, admissionSelector},
	} {
		deployment, err := utils.Run(exec.Command(
			"kubectl", "get", "deployment", component.name, "-n", managerNamespace,
			"-o", "jsonpath={.spec.replicas},{.status.readyReplicas},{.status.availableReplicas}",
		))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(deployment).To(Equal("2,2,2"), component.name)
		pods, err := runningPods(component.selector)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pods).To(HaveLen(2), component.name)

		pdb, err := utils.Run(exec.Command(
			"kubectl", "get", "pdb", component.name, "-n", managerNamespace,
			"-o", "jsonpath={.spec.minAvailable}",
		))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pdb).To(Equal("1"), component.name)
	}

	certificate, err := utils.Run(exec.Command(
		"kubectl", "get", "certificate", "breakglass-operator-serving-cert", "-n", managerNamespace,
		"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}",
	))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(certificate).To(Equal("True"))

	// The webhook Service must route only to the admission pods (ADR-005).
	endpoints, err := readyWebhookEndpointAddresses()
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(endpoints).To(HaveLen(2))
	admissionIPs, err := utils.Run(exec.Command(
		"kubectl", "get", "pods", "-n", managerNamespace, "-l", admissionSelector,
		"-o", "jsonpath={range .items[*]}{.status.podIP}{'\\n'}{end}",
	))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(utils.GetNonEmptyLines(admissionIPs)).To(ContainElements(endpoints))
}

// verifyAdmissionIdentity proves that admission runs as its own ServiceAccount,
// which may read access objects but can neither grant nor change access
// (ADR-005), while the manager keeps the grant rights.
func verifyAdmissionIdentity() {
	serviceAccount, err := utils.Run(exec.Command(
		"kubectl", "get", "deployment", admissionName, "-n", managerNamespace,
		"-o", "jsonpath={.spec.template.spec.serviceAccountName}",
	))
	Expect(err).NotTo(HaveOccurred())
	Expect(serviceAccount).To(Equal(admissionName))

	admission := "system:serviceaccount:" + managerNamespace + ":" + admissionName
	manager := "system:serviceaccount:" + managerNamespace + ":" + managerName
	for _, check := range []struct {
		user, namespace string
		verbResource    []string
		allowed         bool
	}{
		{admission, controlNamespace, []string{"list", "breakglasssessions.access.breakglass.io"}, true},
		{admission, controlNamespace, []string{"get", "accessprofiles.access.breakglass.io"}, true},
		{admission, "", []string{"create", "subjectaccessreviews.authorization.k8s.io"}, true},
		{admission, controlNamespace, []string{"create", "breakglasssessions.access.breakglass.io"}, false},
		{admission, controlNamespace, []string{
			"update", "breakglasssessions.access.breakglass.io", "--subresource=status",
		}, false},
		{admission, targetNamespace, []string{"create", "rolebindings.rbac.authorization.k8s.io"}, false},
		{admission, "", []string{"bind", "clusterroles.rbac.authorization.k8s.io/" + curatedRoleName}, false},
		{admission, "", []string{"escalate", "clusterroles.rbac.authorization.k8s.io"}, false},
		{manager, targetNamespace, []string{"create", "rolebindings.rbac.authorization.k8s.io"}, true},
		{manager, "", []string{"bind", "clusterroles.rbac.authorization.k8s.io/" + curatedRoleName}, true},
	} {
		args := append([]string{"auth", "can-i", "--as=" + check.user}, check.verbResource...)
		if check.namespace != "" {
			args = append(args, "-n", check.namespace)
		}
		output, _ := utils.Run(exec.Command("kubectl", args...))
		want := "no"
		if check.allowed {
			want = "yes"
		}
		// kubectl may print warnings (for example for cluster-scoped
		// resources) before the answer, which is always the last line.
		lines := strings.Split(strings.TrimSpace(output), "\n")
		answer := strings.TrimSpace(lines[len(lines)-1])
		Expect(answer).To(Equal(want), "%s %v in %q", check.user, check.verbResource, check.namespace)
	}
}

// requireDrainDenial requires the drain check to deny deleting the teardown
// namespace because it still holds the teardown session.
func requireDrainDenial() {
	Eventually(func(g Gomega) {
		_, deleteErr := utils.Run(exec.Command("kubectl", "delete", "namespace", teardownNamespace, "--wait=false"))
		g.Expect(deleteErr).To(HaveOccurred())
		g.Expect(deleteErr.Error()).To(ContainSubstring(
			"still holds 1 BreakGlassSession(s) (" + teardownSessionName + ")"))
	}, time.Minute, time.Second).Should(Succeed())
	Expect(namespacePhase(teardownNamespace)).To(Equal("Active"))
}

func readyPods(selector string) []string {
	pods, err := runningPods(selector)
	Expect(err).NotTo(HaveOccurred())
	return pods
}

func runningPods(selector string) ([]string, error) {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "pods", "-n", managerNamespace, "-l", selector,
		"-o", "jsonpath={range .items[?(@.status.phase=='Running')]}{.metadata.name}{'\\n'}{end}",
	))
	if err != nil {
		return nil, err
	}
	return utils.GetNonEmptyLines(output), nil
}

func podUIDs(selector string) []string {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "pods", "-n", managerNamespace, "-l", selector,
		"-o", "jsonpath={range .items[?(@.status.phase=='Running')]}{.metadata.uid}{'\\n'}{end}",
	))
	Expect(err).NotTo(HaveOccurred())
	return utils.GetNonEmptyLines(output)
}

func readyWebhookEndpointAddresses() ([]string, error) {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "endpointslices.discovery.k8s.io", "-n", managerNamespace,
		"-l", "kubernetes.io/service-name=breakglass-operator-webhook-service",
		"-o", "jsonpath={range .items[*].endpoints[?(@.conditions.ready==true)]}{.addresses[0]}{'\\n'}{end}",
	))
	if err != nil {
		return nil, err
	}
	return utils.GetNonEmptyLines(output), nil
}

func managerIsStopped() error {
	return deploymentIsStopped(managerName, managerSelector)()
}

// deploymentIsStopped reports whether a Deployment targets zero replicas and
// none of its pods runs any more.
func deploymentIsStopped(name, selector string) func() error {
	return func() error {
		replicas, err := utils.Run(exec.Command(
			"kubectl", "get", "deployment", name, "-n", managerNamespace,
			"-o", "jsonpath={.spec.replicas}",
		))
		if err != nil {
			return fmt.Errorf("read %s replica target: %w", name, err)
		}

		pods, err := runningPods(selector)
		if err != nil {
			return fmt.Errorf("read %s pods: %w", name, err)
		}

		if strings.TrimSpace(replicas) != "0" || len(pods) != 0 {
			return fmt.Errorf(
				"%s outage has not converged: desired replicas=%q, running pods=%v",
				name, strings.TrimSpace(replicas), pods,
			)
		}
		return nil
	}
}

func scaleDeployment(name string, replicas int) {
	_, err := utils.Run(exec.Command(
		"kubectl", "scale", "deployment", name, "-n", managerNamespace, fmt.Sprintf("--replicas=%d", replicas),
	))
	Expect(err).NotTo(HaveOccurred())
}

func restoreDeployment(name string) {
	By("restoring " + name + " replicas after the outage simulation")
	_, err := utils.Run(exec.Command(
		"kubectl", "scale", "deployment", name, "-n", managerNamespace, "--replicas=2",
	))
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "warning: could not restore %s replicas: %v\n", name, err)
	}
}

func reportProductionDiagnostics() {
	commands := []struct {
		name string
		args []string
	}{
		{"deployments", []string{"get", "deployment", managerName, admissionName, "-n", managerNamespace, "-o", "wide"}},
		{"pods", []string{"get", "pods", "-n", managerNamespace, "-o", "wide"}},
		{"webhook endpoint slices", []string{
			"get", "endpointslices.discovery.k8s.io", "-n", managerNamespace,
			"-l", "kubernetes.io/service-name=breakglass-operator-webhook-service", "-o", "yaml",
		}},
		{"admission logs", []string{
			"logs", "-n", managerNamespace, "-l", admissionSelector, "--tail=50", "--prefix",
		}},
		{"events", []string{"get", "events", "-n", managerNamespace, "--sort-by=.lastTimestamp"}},
	}
	for _, command := range commands {
		output, err := utils.Run(exec.Command("kubectl", command.args...))
		if err != nil {
			_, _ = fmt.Fprintf(GinkgoWriter, "diagnostic %s failed: %v\\n", command.name, err)
			continue
		}
		_, _ = fmt.Fprintf(GinkgoWriter, "diagnostic %s:\\n%s\\n", command.name, strings.TrimSpace(output))
	}
}

func certificateSecretUID() string {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "secret", webhookSecretName(), "-n", managerNamespace, "-o", "jsonpath={.metadata.uid}",
	))
	Expect(err).NotTo(HaveOccurred())
	Expect(output).NotTo(BeEmpty())
	return output
}

func certificateSecretWasReissued(previousUID string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command(
			"kubectl", "get", "secret", webhookSecretName(), "-n", managerNamespace, "-o", "jsonpath={.metadata.uid}",
		))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).NotTo(Equal(previousUID))
	}
}

func createSession(name string) error {
	return createSessionWithDuration(name, "1m")
}

func createSessionWithDuration(name, duration string) error {
	return createSessionIn(controlNamespace, name, duration)
}

func createSessionIn(namespace, name, duration string) error {
	_, err := applyManifestAs(requesterName, fmt.Sprintf(`
apiVersion: access.breakglass.io/v1alpha1
kind: BreakGlassSession
metadata:
  name: %s
  namespace: %s
spec:
  accessProfile: %s
  duration: %q
  reason: "Production HA and fail-closed admission verification"
`, name, namespace, accessProfileName, duration))
	return err
}

func sessionIsActive(name string) func(Gomega) {
	return sessionIsActiveIn(controlNamespace, name)
}

func sessionIsActiveIn(namespace, name string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command(
			"kubectl", "--as="+requesterName, "-n", namespace, "get", "breakglasssession", name,
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

func sessionPhase(name string) string {
	output, err := utils.Run(exec.Command(
		"kubectl", "-n", controlNamespace, "get", "breakglasssession", name, "-o", "jsonpath={.status.phase}",
	))
	Expect(err).NotTo(HaveOccurred())
	return output
}

func sessionHasPhase(name, phase string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command("kubectl", "-n", controlNamespace, "get", "breakglasssession", name, "-o", "jsonpath={.status.phase}"))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal(phase))
	}
}

func sessionHasPassedExpiry(name string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command("kubectl", "-n", controlNamespace, "get", "breakglasssession", name, "-o", "jsonpath={.status.expiresAt}"))
		g.Expect(err).NotTo(HaveOccurred())
		expiresAt, err := time.Parse(time.RFC3339, output)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(time.Now()).To(BeTemporally(">", expiresAt))
	}
}

func sessionBindingName(name string) string {
	bindingName, _ := sessionBindingReference(name)
	return bindingName
}

func sessionBindingReference(name string) (string, string) {
	output, err := utils.Run(exec.Command(
		"kubectl", "-n", controlNamespace, "get", "breakglasssession", name,
		"-o", "jsonpath={.status.bindingRef.name},{.status.bindingRef.uid}",
	))
	Expect(err).NotTo(HaveOccurred())
	parts := strings.Split(output, ",")
	Expect(parts).To(HaveLen(2))
	Expect(parts[0]).NotTo(BeEmpty())
	Expect(parts[1]).NotTo(BeEmpty())
	return parts[0], parts[1]
}

func roleBindingUID(name string) string {
	output, err := utils.Run(exec.Command(
		"kubectl", "get", "rolebinding", name, "-n", targetNamespace, "-o", "jsonpath={.metadata.uid}",
	))
	Expect(err).NotTo(HaveOccurred())
	Expect(output).NotTo(BeEmpty())
	return output
}

func sessionIsSuspendedForCuratedRole(name, reason string) func(Gomega) {
	return func(g Gomega) {
		output, err := utils.Run(exec.Command(
			"kubectl", "-n", controlNamespace, "get", "breakglasssession", name,
			"-o", "jsonpath={.status.phase},{.status.conditions[?(@.type=='CuratedRoleValid')].reason}",
		))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("Suspended," + reason))
	}
}

// expiryGuardRemovedBinding requires a successful guard Job whose log names
// the binding, so the removal is attributable to the guard.
func expiryGuardRemovedBinding(bindingName string) func(Gomega) {
	return func(g Gomega) {
		logs, err := utils.Run(exec.Command(
			"kubectl", "logs", "-n", managerNamespace, "-l", "app.kubernetes.io/component=expiry-guard",
			"--tail=-1", "--prefix", "--max-log-requests=10",
		))
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(logs).To(ContainSubstring("Deleted RoleBinding of expired BreakGlassSession"))
		g.Expect(logs).To(ContainSubstring(bindingName))
	}
}

func bindingIsDeleted(name string) func(Gomega) {
	return func(g Gomega) {
		_, err := utils.Run(exec.Command("kubectl", "get", "rolebinding", name, "-n", targetNamespace))
		g.Expect(err).To(HaveOccurred())
	}
}

func sessionIsDeleted(name string) func(Gomega) {
	return func(g Gomega) {
		_, err := utils.Run(exec.Command("kubectl", "-n", controlNamespace, "get", "breakglasssession", name))
		g.Expect(err).To(HaveOccurred())
	}
}

func namespaceIsDeleted(name string) func(Gomega) {
	return func(g Gomega) {
		_, err := utils.Run(exec.Command("kubectl", "get", "namespace", name))
		g.Expect(err).To(HaveOccurred())
	}
}

func namespacePhase(name string) string {
	output, err := utils.Run(exec.Command("kubectl", "get", "namespace", name, "-o", "jsonpath={.status.phase}"))
	Expect(err).NotTo(HaveOccurred())
	return output
}

// waitForNoSessions waits, best effort, until a control namespace holds no
// sessions, so that teardown can delete it through the drain check.
func waitForNoSessions(namespace string) {
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		output, err := utils.Run(exec.Command(
			"kubectl", "-n", namespace, "get", "breakglasssessions", "-o", "name", "--ignore-not-found",
		))
		if err != nil || strings.TrimSpace(output) == "" {
			return
		}
		time.Sleep(2 * time.Second)
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "warning: sessions remain in %s; its deletion will be denied\n", namespace)
}

func resetCuratedRole() {
	_, err := utils.Run(exec.Command(
		"kubectl", "apply", "-f", "config/samples/rbac_breakglass_pod_observer_clusterrole.yaml",
	))
	Expect(err).NotTo(HaveOccurred())
}

func revokeSession(name string) {
	_, err := utils.Run(exec.Command(
		"kubectl", "-n", controlNamespace, "patch", "breakglasssession", name, "--type=merge", "-p", `{"spec":{"revoked":true}}`,
	))
	Expect(err).NotTo(HaveOccurred())
	Eventually(func(g Gomega) {
		output, err := utils.Run(exec.Command("kubectl", "-n", controlNamespace, "get", "breakglasssession", name, "-o", "jsonpath={.status.phase}"))
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
kind: RoleBinding
metadata:
  name: breakglass-production-e2e-requester-binding
  namespace: breakglass-access
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-production-e2e-requester
subjects:
  - kind: User
    name: production-e2e-requester
    apiGroup: rbac.authorization.k8s.io
`

// teardownAccess is the profile and requester binding in the second control
// namespace. The requester ClusterRole already permits use of a profile with
// this name.
const teardownAccess = `
apiVersion: access.breakglass.io/v1alpha1
kind: AccessProfile
metadata:
  name: production-pod-observer
  namespace: breakglass-teardown
spec:
  roleRef:
    kind: ClusterRole
    name: breakglass-pod-observer
  targetNamespace: production
  maxDuration: 30m
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: breakglass-production-e2e-requester-binding
  namespace: breakglass-teardown
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-production-e2e-requester
subjects:
  - kind: User
    name: production-e2e-requester
    apiGroup: rbac.authorization.k8s.io
`
