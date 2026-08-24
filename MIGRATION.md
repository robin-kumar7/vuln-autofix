# Migrating from `ddi.ai.agents/auto-vuln-fixer`

Nothing breaks on day one: the old reusable workflow in `ddi.ai.agents` is
untouched, so existing callers keep running until they are moved.

## Per-repo change

```diff
 jobs:
   auto-vuln-fix:
-    uses: Infoblox-CTO/ddi.ai.agents/.github/workflows/auto-vuln-fix-reusable.yml@v1.0.0
+    uses: Infoblox-CTO/vuln-autofix/.github/workflows/vuln-autofix-reusable.yml@v1
     permissions:
       contents: write
       pull-requests: write
       actions: read
     with:
       target_branch: ${{ vars.TARGET_BRANCH || 'main' }}
       service_name: cdc-grpc-in
-      fixer_ref: ${{ vars.VULN_FIXER_REF || 'v1.0.0' }}
-      artifact_retention_days: ${{ vars.VULN_FIXER_ARTIFACT_RETENTION_DAYS || '7' }}
+      config_api_url: https://analytics.example.com/api
       pr_branch: auto-fix-vulns-daily
     secrets: inherit
```

`fixer_ref` is gone — the scripts ship inside the action, so the single `@v1`
pins both. `VULN_FIXER_REF` and `VULN_FIXER_ARTIFACT_RETENTION_DAYS` repo
variables become unused.

One new org secret is needed for the config and report-back endpoints:
`VULN_AUTOFIX_API_TOKEN`.

## Registration

Service registration moves from a PR against `config/services-config.yaml` to
the CVE Fix UI (**Repos → Register service**), which validates the repo, the
build paths and the base image before saving. The 105 existing entries are
imported once; `config/services-config.yaml` here is the generated fallback
snapshot, not a file to hand-edit.

## Behaviour changes

| Before | After |
|---|---|
| Weighted risk score; every finding scored `auto_apply` (see README) | Explicit policy: patch/minor auto-apply, major and stdlib always reviewed |
| Findings with no published fix were dropped from `risk-decisions.jsonl` | Emitted as `skip_auto`, so they reach the review queue and the CVE Fix UI |
| `review-queue.md` columns: Risk, Confidence | Bump, Severity — the score that decided nothing is gone |
| `parse-fix.sh --mode parse` scraped Wiz text output | Removed; findings come from the JSON parsers |
| `MODE` had to be `heuristic` | Ignored |
| No schema, no lint, no tests | `config/schema.json`, `scripts/lint-config.sh`, `tests/run-tests.sh`, CI |

Legacy config fields are accepted and ignored, so a service can migrate its
workflow before its config is cleaned up.

## Fixed along the way

- `version-selector.sh`: a `reasons` array was reset only inside the
  parseable branch, so an unparseable version contaminated every later row.
- `decide.sh` / `parse-fix.sh`: an `EXIT` trap whose last command was a
  failing `[[ -f ]]` clobbered the script's exit status, failing clean runs.
- `scan-and-fix.sh`: `log_info "Command: $@"` (shellcheck SC2145) logged
  multi-word commands wrong.
- `bc` was an undeclared dependency of the weight validation, which is gone.
- Docs said minor jumps over 10 were skipped; the threshold has been 20.
- `yq` was installed from `/latest/download`, so an upstream release could
  change eval semantics under every service. Now pinned.
