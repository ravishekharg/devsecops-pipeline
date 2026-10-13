#!/usr/bin/env bash
# Kubernetes manifests: kube-linter (privileged, root, missing limits/probes, writable root FS)
# and trivy's misconfiguration checks.
source "$(dirname "$0")/lib.sh"
log "Kubernetes manifests (kube-linter, trivy config)"
run_tool "$KUBE_LINTER" lint --config /src/ci/kube-linter.yaml /src/k8s
TOOL_OPTS="$TRIVY_OPTS" run_tool "$TRIVY" config --quiet --severity HIGH,CRITICAL --exit-code 1 /src/k8s
