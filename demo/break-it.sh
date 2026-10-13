#!/usr/bin/env bash
# Proof that the gates work: a green pipeline only means something if it goes red on real
# problems. For each gate, take a clean copy of the repo, introduce one typical flaw, commit it,
# run just that gate, and require it to FAIL. The repo itself is never modified. (Unit tests are
# skipped when building, so a later gate is tested on its own: the headers unit test would
# otherwise catch the DAST case first.)
#
#   bash demo/break-it.sh            # all cases
#   bash demo/break-it.sh sast deps  # some
set -uo pipefail
SRC=$(cd "$(dirname "$0")/.." && pwd)
CASES=${*:-secret sast deps dockerfile manifest image dast}
RESULTS=()

flaw() {  # flaw <case> <dir>: introduce the flaw for this case
  local d=$2
  case $1 in
    secret)      # a GitHub token committed to config (generated now, so no real-looking token is ever in this repo)
      printf 'GITHUB_TOKEN = "ghp_%s"\n' "$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)" > "$d/app/settings.py" ;;
    sast)        # SQL built with an f-string: injection
      sed -i "s|conn.execute(\"SELECT id, owner, body FROM notes WHERE owner = ? ORDER BY id\", (owner,))|conn.execute(f\"SELECT id, owner, body FROM notes WHERE owner = '{owner}' ORDER BY id\")|" "$d/app/main.py" ;;
    deps)        # a dependency with known CVEs (requests 2.19.1: CVE-2018-18074, CVE-2023-32681)
      printf 'requests==2.19.1\n' >> "$d/app/requirements.txt" ;;
    dockerfile)  # unpinned base image and running as root
      sed -i -e 's|^FROM python:3.12-slim$|FROM python:latest|' -e 's|^USER 10001$|USER root|' "$d/Dockerfile" ;;
    manifest)    # a privileged container that may run as root
      sed -i -e 's|allowPrivilegeEscalation: false|allowPrivilegeEscalation: true\n            privileged: true|' -e 's|runAsNonRoot: true|runAsNonRoot: false|' "$d/k8s/notes-api.yaml" ;;
    image)       # an old base image (python 3.12.0, Oct 2023) with OS CVEs fixed since
      sed -i 's|^FROM python:3.12-slim$|FROM python:3.12.0-slim|' "$d/Dockerfile" ;;
    dast)        # the security-headers middleware removed
      sed -i 's|    response.headers.update(SECURITY_HEADERS)|    pass|' "$d/app/main.py" ;;
  esac
}

gates() {  # gates <case>: the stage(s) that must fail
  case $1 in
    secret) echo 10-secrets ;; sast) echo 20-sast ;; deps) echo 30-dependencies ;; dockerfile) echo 40-dockerfile ;;
    manifest) echo 50-manifests ;; image) echo "60-test-build 70-image-scan" ;; dast) echo "60-test-build 90-dast" ;;
  esac
}

for c in $CASES; do
  d=$(mktemp -d)
  git -c safe.directory='*' clone -q "$SRC" "$d/repo" && d="$d/repo"
  rsync -a --exclude .git --exclude reports "$SRC/" "$d/"     # include uncommitted work too
  flaw "$c" "$d"
  git -C "$d" add -A && git -C "$d" -c user.name=demo -c user.email=demo@example.com commit -qm "flaw: $c"
  if git -C "$d" diff --quiet HEAD~1 HEAD; then RESULTS+=("ERROR $c: the flaw didn't apply"); continue; fi
  stages=($(gates "$c")); last=${stages[-1]}; caught=0
  for s in "${stages[@]}"; do
    if ! SKIP_TESTS=1 IMAGE="notes-api:flaw-$c" OUT="$d/reports" "$d/ci/$s.sh" > "$d/gate.log" 2>&1; then
      [ "$s" = "$last" ] && caught=1
      break
    fi
  done
  if [ $caught = 1 ]; then
    RESULTS+=("CAUGHT  $c  by $last: $(grep -m1 -E "$(case $c in secret) echo 'leaks found|Finding' ;; sast) echo '[0-9]+ findings?' ;; deps) echo 'CVE-[0-9-]+' ;; dockerfile) echo 'DL[0-9]+' ;; manifest) echo 'check: |privileged' ;; image) echo 'Total: [0-9]+ \(HIGH' ;; dast) echo 'FAIL-NEW: [A-Za-z]' ;; esac)" "$d/gate.log" | sed 's/\x1b\[[0-9;]*m//g' | tr -s ' ' | cut -c1-120)")
  else
    RESULTS+=("MISSED  $c: $last passed with the flaw in place"); tail -20 "$d/gate.log"
  fi
  docker rmi -f "notes-api:flaw-$c" >/dev/null 2>&1
  rm -rf "$(dirname "$d")"
done
printf '\n%s\n' "${RESULTS[@]}"
! printf '%s\n' "${RESULTS[@]}" | grep -qvE '^CAUGHT'
