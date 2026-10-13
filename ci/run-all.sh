#!/usr/bin/env bash
# Every gate in order; stops at the first failure (like a CI pipeline). Reports in reports/.
set -euo pipefail
cd "$(dirname "$0")"
for stage in 10-secrets 20-sast 30-dependencies 40-dockerfile 50-manifests 60-test-build 70-image-scan 80-sbom 90-dast; do
  ./$stage.sh
done
printf '\n\033[1mAll gates passed.\033[0m Reports: %s\n' "${OUT:-$(cd .. && pwd)/reports}"
