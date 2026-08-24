#!/usr/bin/env bash
#
# fetch-config.sh — resolve a service's config, API first, snapshot second.
#
# Registration moved into the CVE Fix UI, so analytics-api is the source of
# truth: config can be edited without a PR, and onboarding a service no longer
# means hand-editing a 2000-line shared YAML.
#
# The contract with scan-and-fix.sh is unchanged and that is the whole point —
# it takes `--config <path>` and reads `.services["<name>"]` plus `.global.*`
# from whatever file it is given, dynamically exporting every key it finds. So
# a served fragment is a drop-in: no script changes, and a new config field
# needs no code change here either.
#
# Falling back matters. A GitHub runner that cannot reach analytics-api must
# still scan, so a non-200 (or no configured URL) uses the snapshot committed
# in this action. That is deliberately LOUD — a stale snapshot silently
# applying stale policy is the failure mode worth shouting about.
set -euo pipefail

SERVICE=""
FALLBACK=""
OUT="/tmp/vuln-autofix-config.yaml"

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") --service NAME --fallback PATH [--out PATH]

  --service   Service key to resolve.
  --fallback  Bundled services-config.yaml used when the API is unavailable.
  --out       Where to write the resolved config (default: $OUT).

Environment:
  CONFIG_API_URL    Base URL of analytics-api. Empty = snapshot only.
  CONFIG_API_TOKEN  Shared secret, sent as X-Scanner-Secret.
EOF
  exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service)  SERVICE="${2:-}"; shift 2 ;;
    --fallback) FALLBACK="${2:-}"; shift 2 ;;
    --out)      OUT="${2:-}"; shift 2 ;;
    -h|--help)  usage 0 ;;
    *) echo "Unknown argument: $1" >&2; usage 1 ;;
  esac
done

[[ -z "$SERVICE"  ]] && { echo "Error: --service is required" >&2; usage 1; }
[[ -z "$FALLBACK" ]] && { echo "Error: --fallback is required" >&2; usage 1; }

API_URL="${CONFIG_API_URL:-}"
API_TOKEN="${CONFIG_API_TOKEN:-}"
SOURCE=""

# emit writes a GitHub Actions step output when running in Actions, and is a
# no-op locally so the script stays runnable by hand.
emit() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
  fi
  printf '  %s=%s\n' "$1" "$2"
}

use_fallback() {
  local why="$1"
  if [[ ! -f "$FALLBACK" ]]; then
    echo "Error: $why, and no fallback config at $FALLBACK" >&2
    exit 1
  fi
  # ::warning:: surfaces in the run summary — a silent fallback is how a
  # service ends up running months-old policy without anyone noticing.
  echo "::warning::vuln-autofix: $why — using the config snapshot bundled in this action, which may be stale"
  cp "$FALLBACK" "$OUT"
  SOURCE="snapshot"
}

if [[ -z "$API_URL" ]]; then
  use_fallback "no CONFIG_API_URL configured"
else
  endpoint="${API_URL%/}/cve/services/${SERVICE}/config"
  echo "Fetching config for '$SERVICE' from $endpoint"
  http_code=0
  # -f is deliberately NOT used: we want the body on a 4xx to log why.
  if http_code=$(curl -sS -o "${OUT}.tmp" -w '%{http_code}' \
                   --max-time 20 --retry 2 --retry-delay 3 \
                   -H "X-Scanner-Secret: ${API_TOKEN}" \
                   -H "Accept: application/yaml" \
                   "$endpoint" 2>/dev/null); then :; else http_code=0; fi

  if [[ "$http_code" == "200" && -s "${OUT}.tmp" ]]; then
    mv "${OUT}.tmp" "$OUT"
    SOURCE="api"
    echo "Config resolved from analytics-api"
  else
    detail="HTTP $http_code"
    if [[ -s "${OUT}.tmp" ]]; then
      detail="$detail: $(head -c 200 "${OUT}.tmp" | tr -d '\n')"
    fi
    rm -f "${OUT}.tmp"
    use_fallback "could not fetch config from analytics-api ($detail)"
  fi
fi

# Validate before anything downstream trusts it. The predecessor had no schema
# and no lint, so a typo'd key surfaced mid-run — after the Docker build.
if ! yq eval '.services' "$OUT" >/dev/null 2>&1; then
  echo "Error: resolved config has no .services section: $OUT" >&2
  exit 1
fi
if [[ "$(yq eval ".services[\"$SERVICE\"] == null" "$OUT" 2>/dev/null || echo true)" == "true" ]]; then
  echo "Error: service '$SERVICE' not found in the resolved config (source: $SOURCE)" >&2
  echo "Hint: register it in the CVE Fix UI, or add it to the snapshot." >&2
  exit 1
fi

echo "Resolved config (source: $SOURCE):"

GO_PRIVATE="$(yq eval ".services[\"$SERVICE\"].go_private // \"\"" "$OUT")"
TEAM="$(yq eval ".services[\"$SERVICE\"].team // \"\"" "$OUT")"

# Read once, here. The predecessor's workflow re-read both with its own yq
# calls, duplicating what load_configuration already does.
emit "source" "$SOURCE"
emit "go_private" "$GO_PRIVATE"
emit "team" "$TEAM"

# PR labels: base pair plus an owning-team label so PRs land in the right
# queue. team is the only field the workflow layer (not the scripts) needs.
LABELS="security,automated"
if [[ -n "$TEAM" && "$TEAM" != "null" ]]; then
  LABELS="${LABELS},team:${TEAM}"
fi
emit "pr_labels" "$LABELS"
