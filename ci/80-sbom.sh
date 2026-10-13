#!/usr/bin/env bash
# SBOM: what's in the image, in CycloneDX and SPDX. Kept as a build artifact and (on main)
# attached to the pushed image as a signed attestation, so "are we affected by CVE-X?" is a
# query over SBOMs rather than a rebuild of every image.
source "$(dirname "$0")/lib.sh"
log "SBOM (syft)"
[ -f "$OUT/image.tar" ] || docker save "$IMAGE" -o "$OUT/image.tar"
TOOL_OPTS="--user 0" COPY_IN="$OUT/image.tar:/image.tar" run_tool "$SYFT" scan docker-archive:/image.tar \
  -o cyclonedx-json=/out/sbom.cdx.json -o spdx-json=/out/sbom.spdx.json
echo "packages in SBOM: $(grep -o '"bom-ref"' "$OUT/sbom.cdx.json" | wc -l)"
