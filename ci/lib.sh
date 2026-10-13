# Shared by every stage. The pipeline logic lives in these scripts, not in CI YAML, so GitHub
# Actions, Jenkins and GitLab CI run exactly the same gates (and so does a laptop).
#
# Tools run as pinned containers. Source goes in with `docker cp` rather than a bind mount: on a
# CI agent that talks to a remote or host Docker daemon (Jenkins in a container, GitLab dind)
# the agent's workspace path doesn't exist on the daemon's machine, so -v $PWD:/src silently
# mounts an empty directory. Copying works everywhere.
set -euo pipefail
ROOT=${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
# shellcheck source=tools.env
source "$ROOT/ci/tools.env"
OUT=${OUT:-$ROOT/reports}
IMAGE=${IMAGE:-notes-api:ci}
mkdir -p "$OUT"

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# run_tool <image> [args...]
#   The repo (minus reports/) is copied to /src, an empty /out is created; whatever the tool
#   writes to /out lands in $OUT. TOOL_OPTS adds `docker create` options; COPY_IN="local:remote"
#   copies one extra file in. Returns the tool's exit code.
run_tool() {
  local image=$1; shift
  local cid rc=0 empty
  # shellcheck disable=SC2086
  cid=$(docker create ${TOOL_OPTS:-} -w /src "$image" "$@")
  empty=$(mktemp -d)
  tar -C "$ROOT" --exclude=./reports --transform 's,^\.,src,' -cf - . | docker cp - "$cid:/"
  tar -C "$empty" --transform 's,^\.,out,' -cf - . | docker cp - "$cid:/"
  rmdir "$empty"
  if [ -n "${COPY_IN:-}" ]; then docker cp "${COPY_IN%%:*}" "$cid:${COPY_IN#*:}"; fi
  docker start -a "$cid" || rc=$?
  docker cp "$cid:/out/." "$OUT/" 2>/dev/null || true
  docker rm -f "$cid" >/dev/null
  return $rc
}

# Trivy's vulnerability DB is cached in a named volume between runs (named volumes live on the
# daemon, so they work where bind mounts don't).
TRIVY_OPTS="-v devsecops-trivy-cache:/root/.cache/trivy"
