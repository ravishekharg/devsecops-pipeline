#!/usr/bin/env bash
# DAST: run the built image and point OWASP ZAP's baseline scan at it. Rules listed as FAIL in
# ci/zap-rules.tsv (missing security headers, version leaks, ...) fail the stage.
source "$(dirname "$0")/lib.sh"
log "dynamic scan (ZAP baseline against the running image)"
net="dast-$$"
docker network create "$net" >/dev/null
cleanup() { docker rm -f "$net-app" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$net-app" --network "$net" --network-alias app -e API_TOKEN=dast-token \
  --read-only --tmpfs /tmp --cap-drop ALL "$IMAGE" >/dev/null
for _ in $(seq 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$net-app")" = healthy ] && break; sleep 1
done
cid=$(docker create --network "$net" -t "$ZAP" zap-baseline.py -t http://app:8000/notes?owner=demo \
  -c rules.tsv -J zap.json -r zap.html -I -s)
# ZAP reads its rules from, and writes reports to, /zap/wrk as the zap user (uid 1000).
wrk=$(mktemp -d); cp "$ROOT/ci/zap-rules.tsv" "$wrk/rules.tsv"
tar -C "$wrk" --owner=1000 --group=1000 --transform 's,^\.,zap/wrk,' -cf - . | docker cp -a - "$cid:/"
rm -rf "$wrk"
rc=0; docker start -a "$cid" || rc=$?
mkdir -p "$OUT/zap"; docker cp "$cid:/zap/wrk/." "$OUT/zap/" 2>/dev/null || true
docker rm -f "$cid" >/dev/null
# zap-baseline: 0 = pass, 1 = a FAIL rule triggered, 2 = warnings only (-I ignores those), 3 = error
exit $rc
