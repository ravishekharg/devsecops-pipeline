#!/usr/bin/env bash
# Continuous re-scan: new CVEs are published every day, so an image that passed every gate at release can be
# vulnerable a week later without anyone changing a line. This re-checks what was SHIPPED, without pulling or
# rebuilding it: it verifies the image's signed SBOM attestation (only an SBOM signed by this repository's pipeline on
# main is trusted), then scans that SBOM against today's vulnerability database.
#
#   REF=ghcr.io/<owner>/notes-api:<tag> IDENTITY_REGEXP=... bash ci/96-rescan.sh   a published image
#   SBOM_FILE=reports/old.cdx.json bash ci/96-rescan.sh                             an SBOM file (self-test)
# Exit 1 when there are HIGH/CRITICAL CVEs with a fix available; reports/rescan.json and reports/rescan.md say which.
source "$(dirname "$0")/lib.sh"
log "re-scan of a shipped image's SBOM against today's vulnerability database"

sbom=$OUT/rescan-sbom.cdx.json
if [ -n "${SBOM_FILE:-}" ]; then
  cp "$SBOM_FILE" "$sbom"
  subject=$SBOM_FILE
else
  : "${REF:?REF (an image reference) or SBOM_FILE is required}"
  : "${IDENTITY_REGEXP:?IDENTITY_REGEXP: which signer to trust, e.g. ^https://github.com/<repo>/.github/workflows/pipeline.yml@refs/heads/main$}"
  # an unsigned SBOM, or one signed by anyone else, proves nothing about the image: refuse to scan it
  cosign verify-attestation "$REF" --type cyclonedx \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com 2>/dev/null \
    | head -1 | jq -r .payload | base64 -d | jq .predicate > "$sbom"
  [ -s "$sbom" ] && [ "$(jq -r .bomFormat "$sbom")" = CycloneDX ] || { echo "no verified CycloneDX SBOM on $REF"; exit 2; }
  subject=$REF
fi
echo "subject: $subject ($(jq '.components | length' "$sbom") components)"

rc=0
TOOL_OPTS="$TRIVY_OPTS" COPY_IN="$sbom:/sbom.cdx.json" run_tool "$TRIVY" sbom --quiet /sbom.cdx.json \
  --severity HIGH,CRITICAL --ignore-unfixed --format json --output /out/rescan.json || rc=$?
[ -s "$OUT/rescan.json" ] || { echo "trivy produced no report (exit $rc)"; exit 2; }

jq -r --arg s "$subject" '
  [.Results[]?.Vulnerabilities[]?] as $v
  | "## Re-scan of \($s)\n",
    (if ($v | length) == 0 then "No HIGH/CRITICAL vulnerabilities with a fix available."
     else "\($v | length) HIGH/CRITICAL vulnerabilities with a fix available:\n\n| CVE | Severity | Package | Installed | Fixed in |\n|---|---|---|---|---|",
          ($v | sort_by(.Severity, .PkgName) | .[] | "| \(.VulnerabilityID) | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion) |")
     end)' "$OUT/rescan.json" > "$OUT/rescan.md"
cat "$OUT/rescan.md"
count=$(jq '[.Results[]?.Vulnerabilities[]?] | length' "$OUT/rescan.json")
[ "$count" = 0 ]
