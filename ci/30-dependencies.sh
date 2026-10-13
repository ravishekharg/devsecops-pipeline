#!/usr/bin/env bash
# SCA: known vulnerabilities in the declared Python dependencies. Fails on HIGH/CRITICAL that
# have a fixed version (an unfixed CVE can't be acted on by bumping; it's tracked, not gated).
source "$(dirname "$0")/lib.sh"
log "dependencies (trivy fs)"
TOOL_OPTS="$TRIVY_OPTS" run_tool "$TRIVY" fs --quiet --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed \
  --exit-code 1 --format table /src/app
