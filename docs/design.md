# Design notes

## What the pipeline defends against
| Threat | Control here | Stage |
|---|---|---|
| Credentials committed to git | gitleaks over full history; secrets only from the environment / CI credentials | 10 |
| Injection and other coding flaws | semgrep public packs + project rules; parameterised SQL; input validation | 20 |
| Known-vulnerable dependencies | trivy over a **fully pinned, hashed** lockfile | 30, 70 |
| Dependency confusion / tampered packages | `--require-hashes`: pip refuses anything whose hash isn't in the lockfile | 60 |
| Insecure container build | hadolint; multi-stage, no pip in the runtime image, fixed non-root UID | 40 |
| Insecure deployment config | kube-linter, trivy config; Pod Security `restricted` on the namespace | 50 |
| Vulnerable base image | trivy image scan of the exact built image | 70 |
| Not knowing what's deployed | SBOM per image, attached as a signed attestation | 80, 95 |
| Misconfigured running service | ZAP baseline against the container | 90 |
| Images that bypassed the pipeline | Kyverno admits only images signed by the pipeline key with an SBOM attestation, from our registry, pinned to the verified digest | 95 |
| Compromised CI tooling | Scanner images pinned by digest, actions pinned by commit SHA, least-privilege workflow token (write scopes only in the job that needs them) | all |

## Why gates fail only on fixable HIGH/CRITICAL
A gate that fails on things nobody can fix gets disabled within a week. Fixable means a version
bump resolves it, so a red build always has a next step. Unfixed CVEs still appear in the reports
and SBOMs, and become gate failures as soon as a fix ships. Exceptions (a false positive, an
accepted risk) belong in a reviewed allow-list with an expiry date (`.trivyignore` with a comment,
semgrep `nosemgrep` with a reason): never by lowering the threshold.

## Signing: key-based vs keyless
- **Key-based** (local, Jenkins): `cosign sign --key`. Works offline and in private registries;
  the private key is a CI credential that must be rotated and protected (in production: a KMS key,
  `cosign sign --key awskms://...`, so the key never leaves the HSM).
- **Keyless** (GitHub `main`): cosign gets a short-lived certificate from Sigstore's Fulcio bound
  to the workflow's OIDC identity (`https://github.com/<repo>/.github/workflows/pipeline.yml@refs/heads/main`),
  and the signature is recorded in the public Rekor log. No key to steal; the policy names the
  identity allowed to sign instead of a key.
- Kyverno can verify either: `attestors.entries.keys` or `attestors.entries.keyless` with
  `subject` and `issuer`.

## The "scanned = shipped" rule
Every stage works on one image built once (`IMAGE`). The SBOM is generated from that image, the
signature is over its digest, and the cluster pins the digest at admission. Rebuilding in a later
job "to push it" would produce a different digest that no scanner has seen.

## Gaps and next steps
- **Secrets at runtime**: the API token comes from a Kubernetes Secret; in production, External
  Secrets Operator from a vault, and the Secret encrypted at rest (KMS).
- **Base image**: python-slim is Debian with a shell; a distroless or Chainguard base would shrink
  the attack surface and the CVE count further.
- **DAST depth**: ZAP baseline is passive. An authenticated API scan (OpenAPI-driven) would test
  auth and input handling on the write endpoints.
- **Policy in the pipeline too**: run the Kyverno policies with the Kyverno CLI against the
  manifests in CI, so a policy violation fails the PR rather than the deploy.
- **Continuous scanning**: re-scan deployed image digests daily (new CVEs appear after release),
  e.g. Trivy Operator in the cluster.
