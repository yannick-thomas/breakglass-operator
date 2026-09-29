#!/usr/bin/env bash
# Read-only preflight for the high-assurance namespaced installer.
set -euo pipefail

target_namespace="${1:-production}"
kubectl_bin="${KUBECTL:-kubectl}"

require() {
  "$@" >/dev/null
  printf 'ok: %s\n' "$*"
}

require "$kubectl_bin" get crd certificates.cert-manager.io
require "$kubectl_bin" get crd issuers.cert-manager.io
require "$kubectl_bin" rollout status deployment/cert-manager -n cert-manager --timeout=30s
require "$kubectl_bin" rollout status deployment/cert-manager-cainjector -n cert-manager --timeout=30s
require "$kubectl_bin" rollout status deployment/cert-manager-webhook -n cert-manager --timeout=30s
require "$kubectl_bin" get namespace "$target_namespace"

printf 'Preflight passed: cert-manager is ready and namespace %q exists.\n' "$target_namespace"
