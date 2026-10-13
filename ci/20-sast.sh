#!/usr/bin/env bash
# SAST: semgrep's Python and Dockerfile rule packs (injection, unsafe deserialisation, weak
# crypto, subprocess with shell=True, ...) plus project rules in ci/semgrep-rules.yaml (the public
# packs miss f-string SQL passed to sqlite3; demo/break-it.sh proves the gate catches it).
# --error makes any finding fail the stage.
source "$(dirname "$0")/lib.sh"
log "static analysis (semgrep)"
run_tool "$SEMGREP" semgrep scan --metrics=off --error --config p/python --config p/dockerfile --config /src/ci/semgrep-rules.yaml \
  --sarif --output /out/semgrep.sarif /src/app /src/Dockerfile
