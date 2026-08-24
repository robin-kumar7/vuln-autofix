#!/usr/bin/env bash
#
# report-run.sh — hand this run's outcome back to the CVE Fix product.
#
# This is what joins the two remediation lanes. The nightly no-AI pass fixes
# what it can cheaply; everything it DECLINES (major version jump, minor jump
# beyond the cap, Go stdlib, no fix published) is the interesting half, because
# that is exactly the work a human or the AI fixer has to pick up. Without this
# report, those CVEs exist only in a workflow artifact nobody opens.
#
# What lands where:
#   auto_apply       -> reported as applied (informational; the PR is the artefact)
#   review_required  -> upserted into cve_findings, so it shows in the CVE Fix UI
#   skip_auto        -> same, flagged as having no automatic path
#
# Best-effort by design: this runs after the PR is created, and a reporting
# outage must never fail a run that already produced a good PR. Every failure
# path warns and exits 0.
set -uo pipefail

SERVICE=""
REPO=""
REF=""
RUN_URL=""
PR_URL=""
BUILD_STATUS=""
DECISIONS="risk-decisions.jsonl"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") --service NAME --repo OWNER/REPO --ref BRANCH [options]

  --run-url URL        Actions run URL, for traceability in the UI.
  --pr-url URL         PR opened by this run, if any.
  --build-status S     passed | failed | skipped
  --decisions PATH     risk-decisions.jsonl (default: $DECISIONS)

Environment:
  CONFIG_API_URL    Base URL of analytics-api. Empty = reporting disabled.
  CONFIG_API_TOKEN  Shared secret, sent as X-Scanner-Secret.
EOF
  exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service)      SERVICE="${2:-}"; shift 2 ;;
    --repo)         REPO="${2:-}"; shift 2 ;;
    --ref)          REF="${2:-}"; shift 2 ;;
    --run-url)      RUN_URL="${2:-}"; shift 2 ;;
    --pr-url)       PR_URL="${2:-}"; shift 2 ;;
    --build-status) BUILD_STATUS="${2:-}"; shift 2 ;;
    --decisions)    DECISIONS="${2:-}"; shift 2 ;;
    -h|--help)      usage 0 ;;
    *) echo "Unknown argument: $1" >&2; usage 1 ;;
  esac
done

API_URL="${CONFIG_API_URL:-}"
if [[ -z "$API_URL" ]]; then
  echo "Reporting skipped: CONFIG_API_URL not set"
  exit 0
fi
[[ -z "$SERVICE" ]] && { echo "Error: --service is required" >&2; usage 1; }

if [[ ! -s "$DECISIONS" ]]; then
  # No decisions file means the scan short-circuited (clean pass, or skipped
  # for want of a scanner). Still report the run so the UI can show that the
  # nightly pass happened and found nothing — silence is ambiguous.
  echo "No decisions file at $DECISIONS; reporting an empty run"
  DECISIONS=""
fi

# jq builds the whole payload so quoting is jq's problem, not the shell's.
# `decisions` is emitted as an array; the API decides which ones become
# findings (it owns the finding_key identity, so it can dedupe against what
# grype already reported rather than inserting a second row for one CVE).
if [[ -n "$DECISIONS" ]]; then
  DECISIONS_JSON=$(jq -s '.' "$DECISIONS" 2>/dev/null || echo '[]')
else
  DECISIONS_JSON='[]'
fi

PAYLOAD=$(jq -n \
  --arg service "$SERVICE" \
  --arg repo "$REPO" \
  --arg ref "$REF" \
  --arg run_url "$RUN_URL" \
  --arg pr_url "$PR_URL" \
  --arg build_status "$BUILD_STATUS" \
  --argjson decisions "$DECISIONS_JSON" \
  '{
     service_name: $service,
     repo: $repo,
     ref: $ref,
     run_url: $run_url,
     pr_url: (if $pr_url == "" then null else $pr_url end),
     build_status: $build_status,
     decisions: $decisions
   }')

endpoint="${API_URL%/}/cve/workflow-runs"
echo "Reporting $(echo "$DECISIONS_JSON" | jq 'length') decision(s) to $endpoint"

http_code=$(curl -sS -o /tmp/report-run-response.txt -w '%{http_code}' \
  --max-time 30 --retry 2 --retry-delay 3 \
  -X POST "$endpoint" \
  -H "Content-Type: application/json" \
  -H "X-Scanner-Secret: ${CONFIG_API_TOKEN:-}" \
  -d "$PAYLOAD" 2>/dev/null) || http_code=0

if [[ "$http_code" == "200" || "$http_code" == "202" ]]; then
  echo "Reported successfully"
  exit 0
fi

# Warn, never fail: the PR is the deliverable and it already exists.
body=""
[[ -s /tmp/report-run-response.txt ]] && body=": $(head -c 200 /tmp/report-run-response.txt | tr -d '\n')"
echo "::warning::vuln-autofix: could not report results to CVE Fix (HTTP ${http_code}${body}). The PR is unaffected; declined findings will not appear in the UI for this run."
exit 0
