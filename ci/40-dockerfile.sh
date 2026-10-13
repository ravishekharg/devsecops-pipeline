#!/usr/bin/env bash
# Dockerfile lint: unpinned bases, running as root, ADD from URLs, apt without cleanup, ...
source "$(dirname "$0")/lib.sh"
log "Dockerfile (hadolint)"
run_tool "$HADOLINT" hadolint --failure-threshold warning /src/Dockerfile
