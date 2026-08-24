# vuln-autofix

Scan a Go service's container image for vulnerable modules, apply the bumps
that are safe to apply unattended, and open a PR with the rest triaged for a
human.

This is the no-AI remediation lane. It pairs with the CVE Fix product's
grype + AI lane: this one handles the cheap, mechanical majority nightly, and
reports what it declines so the AI lane can pick those up.

## Quick start

Register the service in the CVE Fix UI (**Repos → Register service**). The
wizard validates the repo, build paths and base image, then hands you the
workflow file to commit:

```yaml
# .github/workflows/vuln-autofix.yml
name: Vulnerability Scan and Auto-Fix

on:
  schedule:
    - cron: "0 2 * * *"
  workflow_dispatch: {}

concurrency:
  group: vuln-autofix-${{ github.workflow }}-${{ github.ref_name }}
  cancel-in-progress: true

jobs:
  vuln-autofix:
    uses: Infoblox-CTO/vuln-autofix/.github/workflows/vuln-autofix-reusable.yml@v1
    permissions:
      contents: write
      pull-requests: write
      actions: read
    with:
      service_name: my-service
      target_branch: ${{ vars.TARGET_BRANCH || 'main' }}
      config_api_url: https://analytics.example.com/api
    secrets: inherit
```

Secrets come from the org via `secrets: inherit`: `GITPAT`,
`WIZ_CLIENT_ID`, `WIZ_CLIENT_SECRET`, `HARBOR_SERVICES_PROD_USERNAME`,
`HARBOR_SERVICES_PROD_PASSWORD`, and `VULN_AUTOFIX_API_TOKEN` for the config
and report-back endpoints.

## One version knob, not two

The predecessor split itself across two repos: the reusable workflow lived in
`ddi.ai.agents/.github/workflows/`, and at run time it sparse-cloned its own
scripts from that same repo at a **separately specified** ref (`fixer_ref`).
So `uses: …@v1.0.0` pinned the workflow while `fixer_ref: master` floated the
scripts, and the docs disagreed about the defaults (`@main` vs `master`).

Here the scripts ship *inside* a composite action, which GitHub checks out
with the action. `@v1` pins both. There is nothing to clone, no `fixer_ref`,
and no way for the two halves to drift.

## Pipeline

```
go build            → binary
docker build        → image (base_image, dockerfile_path from config)
Wiz or grype        → scan
wiz-parse/grype-parse → parsed-vulns.txt        (one shared TSV contract)
version-selector    → version-recommendations.jsonl
decide              → risk-decisions.jsonl + allowlist.txt
parse-fix           → go mod edit / download / tidy / vendor
verify build        → roll back rather than propose a broken PR
create-pull-request → PR, labelled security,automated,team:<team>
report-run          → declined findings back to CVE Fix
```

Wiz and grype emit the **same** TSV, which is what makes them
interchangeable. Wiz is used when its credentials are present; grype is the
local fallback (`ENABLE_GRYPE_FALLBACK=true`).

## What gets applied automatically

Explicit policy, per service:

```yaml
policy:
  auto_apply: [patch, minor]   # eligible bump types
  max_minor_jump: 20           # larger minor deltas go to review
  never: [major, stdlib]       # never unattended
  require_build_pass: true     # roll back rather than open a broken PR
```

| Situation | Decision |
|---|---|
| patch bump | `auto_apply` |
| minor bump within `max_minor_jump` | `auto_apply` |
| minor bump beyond the cap | `review_required` |
| major bump | `review_required` |
| Go stdlib (needs a toolchain bump) | `review_required` |
| unparseable versions | `review_required` |
| no published fix | `skip_auto` |

Only `auto_apply` reaches `allowlist.txt`, and the allowlist is the only thing
`parse-fix.sh` consults before touching `go.mod`.

### Why this replaced the risk score

The predecessor computed a weighted risk score from seven per-service numbers.
It could not discriminate. With the shipped weights (0.40 / 0.35 / 0.25,
summing to 1.0) the worst realistic input — a CRITICAL finding with a
patch-only bump — scored **0.67** against an auto-apply threshold of **0.85**.
Everything scored `auto_apply`; `skip_auto` was unreachable. `confidence` was
a config constant (0.75) permanently above `min_confidence` (0.70), so that
gate could never bind either. All 105 registered services carried identical
values, so the per-service knobs had never once been varied.

It was also backwards: a higher severity *raised* the risk score, which pushed
a finding toward being **skipped**.

What actually protected people was the version-jump guard in `parse-fix.sh`.
That guard is now the stated policy, where it can be read and tested.

The legacy fields (`mode`, `risk_threshold_auto`, `risk_threshold_review`,
`min_confidence`, `confidence`, `exploit_weight`, `version_weight`,
`cycle_weight`) are still accepted and ignored, with one deprecation notice,
so an unmigrated config keeps working.

## Config

Served by analytics-api so it can be edited in the UI without a PR:

```
GET {config_api_url}/cve/services/{service_name}/config
```

`scan-and-fix.sh` takes `--config <path>` and reads `.services["<name>"]` plus
`.global.*` from whatever file it is handed, dynamically exporting every key it
finds as an env var — so the served fragment is a drop-in, and adding a config
field needs no script change.

If the API is unreachable (or `config_api_url` is empty) the action falls back
to `config/services-config.yaml` bundled here, and says so with a
`::warning::`. That snapshot is generated, not hand-edited.

Validate a config locally:

```bash
bash scripts/lint-config.sh config/services-config.yaml
```

### Fields

| Field | Required | Notes |
|---|---|---|
| `image_name` | ✓ | built and scanned as `<image_name>:scan` |
| `dockerfile_path` | ✓ | relative to `working_directory` |
| `server_build_path` | ✓ | one main package (`./cmd/foo`, or `.`) — `./...` will not work |
| `base_image` | ✓ | passed as `--build-arg BASE_IMAGE` |
| `team` | | becomes the PR label `team:<value>` |
| `build_tags`, `build_ldflags`, `docker_build_extra_args` | | passed through to the builds |
| `go_private` | | `GOPRIVATE`/`GONOSUMDB`; without it private imports 404 through the public proxy |
| `vendor_for_docker` | | `go mod vendor` on the host first, for Dockerfiles that compile in-container |
| `docker_build_context` | | set to `..` for a monorepo module whose Dockerfile COPYs from the repo root |
| `working_directory` | | module subdirectory |
| `policy` | | see above |

## Multi-module monorepos

One matrix leg per module, each with its own `pr_branch` (they will otherwise
fight over one branch) and its own registration with paths relative to the
module directory. `fail-fast: false` so one module does not cancel the rest.
See `templates/caller-workflow.yml.tmpl`.

## Artifacts

Uploaded on every run, retained for `artifact_retention_days`:
`wiz-scan-results.json`, `grype-scan-output.json`, `parsed-vulns.txt`,
`version-recommendations.jsonl`, `risk-decisions.jsonl`, `allowlist.txt`,
`cve-map.txt`, `cve-version-map.txt`, `vuln-fix-summary.md`,
`review-queue.md`.

## Local run

```bash
export ENABLE_GRYPE_FALLBACK=true      # use grype instead of Wiz
bash scripts/scan-and-fix.sh \
  --service my-service \
  --config config/services-config.yaml \
  --repo-root /path/to/repo \
  --dry-run
```

Requires `yq jq awk sed grep go docker`, plus `grype` for the fallback path.

## Tests

```bash
bash tests/run-tests.sh
```

Covers the decision policy (including that a CRITICAL severity does not block
a safe bump — the old model's inversion), that legacy scoring flags are
accepted and ignored, that the config fallback warns, and the
`version-selector` regression where a `reasons` array leaked across loop
iterations.
