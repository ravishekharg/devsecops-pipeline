#!/usr/bin/env bash
# Supply chain, end to end: push the scanned image, sign it and attach its SBOM as a signed
# attestation (cosign), then prove the cluster enforces it in a throwaway kind cluster with
# Kyverno:
#   signed image with SBOM         -> admitted, and its tag rewritten to the verified digest
#   same app, unsigned build       -> rejected
#   image from another registry    -> rejected
# Key-based signing here (works offline and on any CI); on GitHub main the same image is also
# signed keylessly with the workflow's OIDC identity (.github/workflows/pipeline.yml).
#
# Needs: docker, kind, kubectl, helm. KEEP=1 leaves the cluster and registry running.
source "$(dirname "$0")/lib.sh"
CLUSTER=${CLUSTER:-devsecops}
REG_NAME=${REG_NAME:-dsp-registry}
REG_PORT=${REG_PORT:-5002}
REGISTRY_IN_CLUSTER="$REG_NAME:5000"
COSIGN=ghcr.io/sigstore/cosign/cosign:v2.4.1@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31
REGISTRY_IMAGE=registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373
KIND_NODE=${KIND_NODE:-kindest/node:v1.34.0}
KYVERNO_CHART=3.3.4
KCTX="kind-$CLUSTER"
# A kubeconfig of its own: never switch (or, on delete, blank) the machine's current context.
export KUBECONFIG="$OUT/kubeconfig-$CLUSTER"
k() { kubectl --context "$KCTX" "$@"; }

cleanup() {
  [ -n "${KEEP:-}" ] && return
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  docker rm -f "$REG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# cosign in a container with the key material copied in (no bind mounts; see lib.sh)
KEYS=$(mktemp -d)
cosign() {
  local cid rc=0
  cid=$(docker create --user 0 --network host -e COSIGN_PASSWORD="${COSIGN_PASSWORD:-}" -w /k "$COSIGN" "$@")
  tar -C "$KEYS" --transform 's,^\.,k,' -cf - . | docker cp - "$cid:/"
  docker start -a "$cid" || rc=$?
  docker cp "$cid:/k/." "$KEYS/" 2>/dev/null || true
  docker rm -f "$cid" >/dev/null
  return $rc
}

log "registry and kind cluster"
docker inspect "$REG_NAME" >/dev/null 2>&1 || \
  docker run -d --restart=always -p "127.0.0.1:$REG_PORT:5000" --name "$REG_NAME" "$REGISTRY_IMAGE" >/dev/null
if ! kind get clusters | grep -qx "$CLUSTER"; then
  cat <<EOF | kind create cluster --name "$CLUSTER" --image "$KIND_NODE" --wait 120s --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
EOF
fi
for node in $(kind get nodes --name "$CLUSTER"); do
  docker exec "$node" sh -c "mkdir -p /etc/containerd/certs.d/$REGISTRY_IN_CLUSTER && printf '[host.\"http://$REGISTRY_IN_CLUSTER\"]\n' > /etc/containerd/certs.d/$REGISTRY_IN_CLUSTER/hosts.toml"
done
docker network connect kind "$REG_NAME" 2>/dev/null || true

log "push and sign"
TAG=${TAG:-$(date +%Y%m%d%H%M%S)}
docker tag "$IMAGE" "localhost:$REG_PORT/notes-api:$TAG"
docker push -q "localhost:$REG_PORT/notes-api:$TAG" >/dev/null
DIGEST=$(docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "localhost:$REG_PORT/notes-api:$TAG" \
  | grep "localhost:$REG_PORT/notes-api@" | head -1 | cut -d@ -f2)
echo "pushed notes-api:$TAG @ $DIGEST"
if [ -n "${COSIGN_KEY_B64:-}" ]; then          # a CI-held key (Jenkins credential / CI secret)
  echo "$COSIGN_KEY_B64" | base64 -d > "$KEYS/cosign.key"; echo "$COSIGN_PUB_B64" | base64 -d > "$KEYS/cosign.pub"
else                                            # throwaway key pair for this run
  cosign generate-key-pair >/dev/null
fi
[ -f "$OUT/sbom.cdx.json" ] || "$ROOT/ci/80-sbom.sh"
cp "$OUT/sbom.cdx.json" "$KEYS/sbom.cdx.json"
REF="localhost:$REG_PORT/notes-api@$DIGEST"
cosign sign --yes --key cosign.key --allow-insecure-registry --tlog-upload=false "$REF"
cosign attest --yes --key cosign.key --allow-insecure-registry --tlog-upload=false --type cyclonedx --predicate sbom.cdx.json "$REF"
cosign verify --key cosign.pub --allow-insecure-registry --insecure-ignore-tlog "$REF" >/dev/null && echo "signature verifies"

log "Kyverno and the supply-chain policy"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
helm repo update kyverno >/dev/null
helm upgrade --install kyverno kyverno/kyverno --kube-context "$KCTX" -n kyverno --create-namespace \
  --version "$KYVERNO_CHART" --set admissionController.replicas=1 --set features.registryClient.allowInsecure=true \
  --set backgroundController.enabled=false --set cleanupController.enabled=false --set reportsController.enabled=false \
  --wait --timeout 300s 2>&1 >/dev/null | { grep -v 'unrecognized format' || true; } >&2
python3 - "$KEYS/cosign.pub" "$REGISTRY_IN_CLUSTER" "$ROOT/k8s/policy/supply-chain.yaml" > "$OUT/policy.yaml" <<'PY'
import sys
pub, registry, path = open(sys.argv[1]).read().strip(), sys.argv[2], sys.argv[3]
out = []
for line in open(path).read().replace("REGISTRY", registry).splitlines():
    if line.strip() == "PUBLIC_KEY":
        indent = line[: len(line) - len(line.lstrip())]
        out += [indent + l for l in pub.splitlines()]
    else:
        out.append(line)
print("\n".join(out))
PY
for _ in $(seq 30); do k apply -f "$OUT/policy.yaml" >/dev/null 2>&1 && break; sleep 5; done
k wait --for=condition=Ready clusterpolicy/notes-supply-chain --timeout=120s >/dev/null

log "admission tests"
k create namespace notes --dry-run=client -o yaml | k apply -f - >/dev/null
k label namespace notes pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
k -n notes create secret generic notes-api --from-literal=token="$(head -c 24 /dev/urandom | base64)" --dry-run=client -o yaml | k apply -f - >/dev/null

fail=0
expect() {  # expect <admit|reject> <description> <image>
  local want=$1 what=$2 image=$3 out rc=0
  out=$(sed -e "s#registry.example/notes-api:0.1.0#$image#" "$ROOT/k8s/notes-api.yaml" | k apply -f - 2>&1) || rc=$?
  if [ "$want" = admit ] && [ $rc -eq 0 ] && k -n notes rollout status deploy/notes-api --timeout=120s >/dev/null; then
    echo "PASS  admitted: $what"
  elif [ "$want" = reject ] && [ $rc -ne 0 ]; then
    echo "PASS  rejected: $what -> $(echo "$out" | grep -oE "(only-our-registry|signed-with-sbom): .{0,110}" | head -1)"
  else
    echo "FAIL  expected $want: $what"; echo "$out" | tail -5; fail=1
  fi
}
expect admit "signed image with SBOM attestation" "$REGISTRY_IN_CLUSTER/notes-api:$TAG"
deployed=$(k -n notes get deploy notes-api -o jsonpath='{.spec.template.spec.containers[0].image}')
case "$deployed" in *"@$DIGEST") echo "PASS  tag rewritten to the verified digest: ...@${DIGEST:7:12}" ;; *) echo "FAIL  image not pinned to digest: $deployed"; fail=1 ;; esac

# An unsigned build of the same app: same code, different digest, never signed.
printf 'FROM %s\nLABEL built-by=someone-bypassing-the-pipeline\n' "$IMAGE" | docker build -q -t "localhost:$REG_PORT/notes-api:unsigned" - >/dev/null
docker push -q "localhost:$REG_PORT/notes-api:unsigned" >/dev/null
k -n notes delete deploy notes-api --wait >/dev/null
expect reject "unsigned build of the same app" "$REGISTRY_IN_CLUSTER/notes-api:unsigned"
expect reject "image from another registry" "docker.io/library/python:3.12-slim"
exit $fail
