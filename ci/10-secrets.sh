#!/usr/bin/env bash
# Secrets: gitleaks over the whole git history, not just the working tree. A key that was
# committed and deleted later is still in the history, and still has to be rotated.
source "$(dirname "$0")/lib.sh"
log "secrets (gitleaks, full history)"
TOOL_OPTS="--user 0" run_tool "$GITLEAKS" detect --source /src --redact --no-banner \
  --report-format sarif --report-path /out/gitleaks.sarif --exit-code 1
