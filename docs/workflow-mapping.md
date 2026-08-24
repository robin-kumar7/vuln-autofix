# Workflow Mapping: GitHub Action -> Skill

This document maps the current CI workflow behavior to the skill-run procedure.

## Step Mapping

1. Resolve trigger and target branch
- Workflow:
  - Triggers on `schedule` and `workflow_dispatch`.
  - Resolves target branch from repository variable `vars.TARGET_BRANCH`, defaulting to `develop`.
  - Runs remediation against the resolved target branch.
- Skill:
  - For local/manual runs, use the intended default branch as remediation base.
  - For CI parity, treat target branch as workflow-owned configuration (repository variable), not service-config-owned.

2. Checkout and strict config loading
- Workflow:
  - Checks out the resolved target branch.
  - Loads service values from `config/services-config.yaml` for the selected service.
  - Exports build, scan, and risk-scoring variables from the centralized YAML.
  - Exposes artifact retention as `artifact_retention_days` output (`ARTIFACT_RETENTION_DAYS`, default `30`).
- Skill:
  - Load equivalent variables from centralized YAML.
  - Keep defaults aligned with workflow/script exports.

3. Private module and Go environment bootstrap
- Workflow:
  - Configures optional private Git auth via `GITPAT` URL rewrite.
  - Sets `GOPRIVATE` and `GONOSUMDB` when `GO_PRIVATE` is set.
  - Sets `GOPROXY=https://proxy.golang.org,direct`.
  - Uses `actions/setup-go@v5` with `go-version-file: go.mod`.
- Skill:
  - Ensure equivalent auth/proxy setup before dependency or build steps.

4. Build binary and scan image
- Workflow:
  - `CGO_ENABLED=0 go build -v -tags "$BUILD_TAGS" -trimpath -ldflags "$BUILD_LDFLAGS" -o bin/server "$SERVER_BUILD_PATH"`
  - `docker build --progress=plain -f "$DOCKERFILE_PATH" --build-arg BASE_IMAGE="$BASE_IMAGE" $DOCKER_BUILD_EXTRA_ARGS -t "$IMAGE_NAME:scan" .`
- Skill:
  - Run the same build/image commands with values from service config.

5. Wiz guard, auth, and scan
- Workflow:
  - Installs CLI from `https://downloads.wiz.io/v1/wizcli/${WIZ_CLI_VERSION}/wizcli-linux-amd64` (version defaults to `latest` from centralized config/global default).
  - Runs `wiz_guard`: if `WIZ_CLIENT_ID`/`WIZ_CLIENT_SECRET` are missing, skips auth+scan and reports reason in the step summary.
  - If ready, authenticates and runs scan with Critical+High policies and `--file-hashes-scan`.
  - Writes scan results to `wiz-scan-results.json` and raw CLI output to `wiz-scan-raw.txt`.
- Skill:
  - Preserve guard behavior and reporting.
  - Produce and retain `wiz-scan-results.json` as parser input, and retain `wiz-scan-raw.txt` for scan evidence.

6. Parse, recommend, score, and queue review
- Workflow:
  - Parses findings from `wiz-scan-results.json` using [wiz-json-parse.sh](../scripts/wiz-json-parse.sh).
  - Recommends compatible fix versions using [version-selector.sh](../scripts/version-selector.sh).
  - Scores risk using [risk-score.sh](../scripts/risk-score.sh) and writes `risk-decisions.jsonl`.
  - Builds `review-queue.md` from `review_required` and `skip_auto` decisions.
  - Builds `allowlist.txt` from `decision=="auto_apply"`.
- Skill:
  - Preserve the same file formats and decision flow before apply.

7. Apply fixes and detect dependency diffs
- Workflow:
  - Applies allowlisted recommendations via [parse-fix.sh](../scripts/parse-fix.sh) with `--mode apply`.
  - Detects changes in `go.mod`, `go.sum`, and `vendor/`.
- Skill:
  - Keep identical apply and diff-detection behavior.

8. No-change reporting and build validation
- Workflow:
  - If no dependency changes: writes a workflow summary.
  - If dependency changes: rebuilds with same flags and records pass/fail status.
- Skill:
  - Provide explicit no-change messaging and rebuild validation parity.

9. Artifacts and PR automation
- Workflow:
  - Always uploads scan/decision artifacts and uses configurable retention days.
  - Creates PR body from build status, remediation summary, and optional review queue.
  - Cleans stale `auto-fix-vulns-daily` branch when no open PR exists.
  - Creates/updates PR via `peter-evans/create-pull-request@v7`.
  - Uses resolved target branch as PR base.
- Skill:
  - Preserve equivalent artifacts and PR-ready summary content for manual or automated PR creation.

## Behavior Preserved
- Handles CVE and EOL-TECHNOLOGY severities.
- Parses package records safely when package names contain spaces.
- Tracks CVEs per package and per package+fixed-version.
- Scores version safety before selecting a fix target.
- Uses risk gating to build an allowlist of `auto_apply` package/version pairs.
- Reports all candidate fixed versions and applies one allowlisted target.
- Skips large/risky jumps per apply-time guards.
- Marks stdlib findings for toolchain updates.
- Includes manual-remediation findings in summary output.
- Detects and annotates transitive dependency context for manual remediation.
- Restores `go.mod` and `go.sum` when package download fails.
- Reverts dependency edits (`go.mod`, `go.sum`, `vendor/`) when tidy/vendor fails.
- Skips Wiz scan gracefully when credentials are unavailable.
