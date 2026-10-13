# devsecops-pipeline

A CI/CD pipeline where security checks are gates, not reports, and the cluster only runs what
the pipeline signed. It builds a small Python API (`app/`) through ten stages:

| # | Gate | Tool (pinned by digest) | Fails the build on |
|---|---|---|---|
| 10 | Secrets | gitleaks | Any secret in the **whole git history** |
| 20 | SAST | semgrep (public packs + [project rules](ci/semgrep-rules.yaml)) | Any finding |
| 30 | Dependencies | trivy fs | HIGH/CRITICAL CVEs with a fix, across the hashed lockfile |
| 40 | Dockerfile | hadolint | Warnings and errors (unpinned base, root user, ...) |
| 50 | Kubernetes manifests | kube-linter, trivy config | Privileged, root, writable root FS, missing limits/probes, ... |
| 60 | Tests and build | pytest, docker | Failing tests |
| 70 | Image | trivy image | HIGH/CRITICAL CVEs with a fix in OS or language packages |
| 80 | SBOM | syft | (produces CycloneDX + SPDX) |
| 90 | DAST | OWASP ZAP baseline against the running container | Missing security headers, version leaks ([rules](ci/zap-rules.tsv)) |
| 95 | Sign and admit | cosign, Kyverno in kind | Image not signed by the pipeline or without a signed SBOM: **rejected by the cluster** |

Each stage is a script in [`ci/`](ci); GitHub Actions ([`pipeline.yml`](.github/workflows/pipeline.yml))
and Jenkins ([`Jenkinsfile`](Jenkinsfile)) only order them, hold credentials and keep reports.
On `main`, GitHub also publishes the scanned image to GHCR with a **keyless Sigstore signature**
(identity = this workflow), a signed SBOM attestation and **SLSA build provenance**, then verifies
them the way a consumer would.

It's a personal project built for interviews, not code from a former employer.

## Result

**It goes red on real problems.** [`demo/break-it.sh`](demo/break-it.sh) (a CI job) seeds one
typical flaw per gate in a throwaway copy and requires that gate to fail:

| Seeded flaw | Caught by |
|---|---|
| GitHub token committed to config | gitleaks: `leaks found: 1` |
| SQL built with an f-string | semgrep project rule `sql-built-from-strings` |
| `requests==2.19.1` added | trivy: CVE-2018-18074 (HIGH, fixed in 2.20.0) |
| `FROM python:latest`, `USER root` | hadolint: DL3007, DL3002 |
| `privileged: true`, `runAsNonRoot: false` | kube-linter and trivy config |
| Old base image (python 3.12.0) | trivy image: 89 fixable (76 HIGH, 13 CRITICAL) |
| Security-headers middleware removed | ZAP: FAIL on X-Content-Type-Options missing [10021] (its CSP and anti-clickjacking rules only fire on HTML responses; this API returns JSON) |
| Unsigned build of the same app, or an image from another registry | Kyverno: rejected at admission |

**And it found real problems while being built:**
- The image scan found **3 HIGH CVEs in Starlette 0.41.3**, a transitive dependency of FastAPI
  that the dependency scan couldn't see, because `requirements.txt` listed only direct dependencies.
  Fixed with a lockfile: every transitive dependency pinned with hashes (`pip install
  --require-hashes`), so the scan sees everything and a tampered package can't install.
- semgrep's public packs (`p/python`, `p/sql-injection`, `p/owasp-top-ten`) all **missed an
  f-string SQL injection** passed to `sqlite3.execute()`. Hence the project rule, and the seeded
  test that keeps it honest.
- kube-linter flagged the PodDisruptionBudget for not setting `unhealthyPodEvictionPolicy`
  (a crash-looping pod could block node drains).

**Runs on both CI systems, unchanged:** GitHub Actions, and Jenkins in my homelab (job defined
as code, source from Gitea): build #2 passed all nine gates in about two minutes.

## Run it locally
Needs Docker (and kind, kubectl, helm for stage 95).
```bash
bash ci/run-all.sh              # gates 10-90, reports in reports/
bash ci/95-sign-and-admit.sh    # throwaway registry + kind cluster + Kyverno; removed afterwards (KEEP=1 to keep)
bash demo/break-it.sh           # every gate must catch its seeded flaw
```

## Design choices
| Choice | Why |
|---|---|
| Stages are scripts; CI YAML only calls them | Same gates on GitHub, Jenkins, GitLab or a laptop; switching CI isn't a rewrite |
| Scanners run as containers **pinned by digest**; actions pinned by commit SHA | A moved tag or compromised publisher account can't change what runs in the pipeline |
| Source copied into tool containers (`docker cp`), not bind-mounted | Jenkins here runs in a container against the host's Docker daemon: `-v $PWD:/src` would mount an empty directory from the wrong machine |
| Fail on HIGH/CRITICAL **with a fix** | A gate the team can always act on (bump the version); unfixed CVEs are visible in the reports, not blocking |
| Full-history secret scan | A key deleted in a later commit is still in the history, and still has to be rotated |
| The image that's scanned is the image that's signed and pushed | Rebuilding after the scan would sign something nobody scanned |
| Admission control in the cluster (Kyverno `verifyImages`, digest pinning) | Without it, anyone with `kubectl apply` bypasses the whole pipeline |
| Key-based signing locally/Jenkins, keyless (OIDC) on GitHub | Keyless needs an OIDC identity (GitHub provides one); key-based works offline. Kyverno can verify either |

More in [`docs/design.md`](docs/design.md): threat model, what each control stops, and what's not covered.
