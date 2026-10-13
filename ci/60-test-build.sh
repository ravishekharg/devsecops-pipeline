#!/usr/bin/env bash
# Unit tests, then the image build. (SKIP_TESTS=1 builds only; demo/break-it.sh uses it.)
source "$(dirname "$0")/lib.sh"
if [ -z "${SKIP_TESTS:-}" ]; then
  log "unit tests"
  run_tool "$PYTHON" sh -c "pip install -q --root-user-action=ignore --require-hashes -r app/requirements.txt && pip install -q --root-user-action=ignore pytest==8.3.4 httpx==0.28.1 && cd app && python -m pytest -q -p no:cacheprovider"
fi
log "build $IMAGE"
tar -C "$ROOT" --exclude=./reports --exclude=./.git -cf - . | docker build -q -t "$IMAGE" -
