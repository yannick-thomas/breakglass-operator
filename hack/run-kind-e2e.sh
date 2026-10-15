#!/usr/bin/env bash
# Keep every test command off the developer's normal kubeconfig/context.
set -euo pipefail

profile="${1:?expected default, production or helm}"
case "$profile" in
  default) suite=./test/e2e/; installer=kustomize ;;
  production) suite=./test/e2e/production; installer=kustomize ;;
  helm) suite=./test/e2e/production; installer=helm ;;
  *) echo "Unknown E2E profile: $profile" >&2; exit 1 ;;
esac
cluster="${KIND_CLUSTER:?KIND_CLUSTER must name the disposable test cluster}"
case "$cluster" in
  breakglass-operator-*-e2e) ;;
  *) echo "Refusing cluster without the breakglass-operator-*-e2e test naming convention" >&2; exit 1 ;;
esac
kind_bin="${KIND:-kind}"
kubectl_bin="${KUBECTL:-kubectl}"
for tool in "$kind_bin" "$kubectl_bin" docker; do
  command -v "$tool" >/dev/null || {
    echo "Missing E2E prerequisite: $tool. Install Kind, kubectl and Docker before running this target." >&2
    exit 1
  }
done
docker info >/dev/null || {
  echo "Docker is not ready; start its daemon before running Kind E2E." >&2
  exit 1
}

workdir="$(mktemp -d)"
export KUBECONFIG="$workdir/kubeconfig"
export PRODUCTION_INSTALLER="$installer"
context="kind-$cluster"
artifacts="${E2E_ARTIFACT_DIR:-$PWD/e2e-artifacts/$profile}"
mkdir -p "$artifacts"

finish() {
  status=$?
  trap - EXIT
  if [[ "$("$kubectl_bin" config current-context 2>/dev/null || true)" == "$context" ]]; then
    "$kubectl_bin" --context "$context" get pods,jobs,cronjobs -A -o wide > "$artifacts/workloads.txt" 2>&1 || true
    "$kubectl_bin" --context "$context" get events -A --sort-by=.lastTimestamp > "$artifacts/events.txt" 2>&1 || true
    "$kubectl_bin" --context "$context" -n breakglass-operator-system logs \
      -l control-plane=controller-manager --all-containers=true --prefix=true --tail=1000 \
      > "$artifacts/manager.log" 2>&1 || true
    "$kind_bin" export logs "$artifacts/kind-logs" --name "$cluster" >/dev/null 2>&1 || true
  fi
  if [[ "$status" == 0 && "${KEEP_TEST_CLUSTER:-false}" != true ]]; then
    "$kind_bin" delete cluster --name "$cluster"
    rm -r "$workdir"
  else
    echo "Test cluster retained: $cluster"
    echo "Diagnostics: $artifacts"
    echo "Inspect with: KUBECONFIG=$KUBECONFIG $kubectl_bin --context $context get pods -A"
  fi
  exit "$status"
}
trap finish EXIT

if ! "$kind_bin" get clusters | grep -Fxq "$cluster"; then
  if [[ "$profile" == default ]]; then
    "$kind_bin" create cluster --name "$cluster" --kubeconfig "$KUBECONFIG"
  else
    "$kind_bin" create cluster --name "$cluster" --kubeconfig "$KUBECONFIG" \
      --config test/e2e/production/kind-config.yaml
  fi
fi
"$kind_bin" export kubeconfig --name "$cluster" --kubeconfig "$KUBECONFIG"
[[ "$("$kubectl_bin" config current-context)" == "$context" ]]
make capture-kind-compatibility-evidence KIND_CLUSTER="$cluster" \
  COMPATIBILITY_EVIDENCE_DIR="$artifacts/compatibility"
go test -timeout=25m -tags=e2e "$suite" -v -ginkgo.v \
  -ginkgo.junit-report="$artifacts/junit.xml" | tee "$artifacts/test.log"
