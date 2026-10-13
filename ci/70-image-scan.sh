#!/usr/bin/env bash
# Image scan: OS packages and Python packages inside the built image. The image goes in as a
# `docker save` tarball, so the scanner needs no access to the Docker socket.
source "$(dirname "$0")/lib.sh"
log "image vulnerabilities (trivy image $IMAGE)"
docker save "$IMAGE" -o "$OUT/image.tar"
TOOL_OPTS="$TRIVY_OPTS" COPY_IN="$OUT/image.tar:/image.tar" run_tool "$TRIVY" image --quiet --input /image.tar \
  --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --format table
