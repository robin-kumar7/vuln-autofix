#!/usr/bin/env bash
# Compatible with bash and zsh.
[ -n "$ZSH_VERSION" ] && emulate bash
set -euo pipefail

# Wiz JSON parser — converts Wiz JSON scan output to parsed-vulns format.
# Produces the same tab-delimited output as parse-fix.sh parse mode so that
# version-selector.sh, risk-score.sh, and parse-fix.sh apply mode work unchanged.
#
# Usage:
#   ./wiz-json-parse.sh <wiz-json-file> [options]
#
# Options:
#   --parsed FILE          Output file for parsed vulns  (default: parsed-vulns.txt)
#   --cve-map FILE         Output file for CVE map       (default: cve-map.txt)
#   --cve-version-map FILE Output file for CVE-per-version map (default: cve-version-map.txt)
#
# Output format (matches parse-fix.sh):
#   parsed-vulns.txt     — PACKAGE\tVERSION\tFIX_VERSION\tSEVERITY\tCVE_ID

INPUT_FILE="${1:-}"
if [[ -z "$INPUT_FILE" ]]; then
  echo "Usage: $0 <wiz-json-file> [options]" >&2
  exit 1
fi
shift

PARSED_FILE="parsed-vulns.txt"
CVE_MAP_FILE="cve-map.txt"
CVE_VERSION_MAP_FILE="cve-version-map.txt"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --parsed)          PARSED_FILE="${2:-}";          shift 2 ;;
    --cve-map)         CVE_MAP_FILE="${2:-}";          shift 2 ;;
    --cve-version-map) CVE_VERSION_MAP_FILE="${2:-}";  shift 2 ;;
    -h|--help)
      echo "Usage: $0 <wiz-json-file> [options]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [[ ! -f "$INPUT_FILE" ]]; then
  echo "Input file not found: $INPUT_FILE" >&2
  exit 1
fi

: > "$PARSED_FILE"
: > "$CVE_MAP_FILE"
: > "$CVE_VERSION_MAP_FILE"

# HIGH FIX #5: Detect and validate Wiz API version for schema compatibility
api_version=$(jq -r '.apiVersion // "unknown"' "$INPUT_FILE" 2>/dev/null || echo "unknown")
if [[ ! "$api_version" =~ ^(1\.|unknown)$ ]]; then
  echo "Warning: Wiz API version $api_version detected (expected v1.x) - schema may differ" >&2
  echo "  Continuing with v1 schema assumptions..." >&2
fi

# Validate that expected schema paths exist
# Use has() rather than jq -e so that null-valued fields (no findings) don't
# trigger a false schema-mismatch error.
has_libraries=$(jq -r 'if .result | has("libraries") then "true" else "false" end' "$INPUT_FILE" 2>/dev/null || echo "false")
has_eol=$(jq -r 'if .result | has("endOfLifeTechnologies") then "true" else "false" end' "$INPUT_FILE" 2>/dev/null || echo "false")

if [[ "$has_libraries" != "true" && "$has_eol" != "true" ]]; then
  echo "Error: Wiz JSON missing expected .result.libraries and .result.endOfLifeTechnologies fields" >&2
  echo "  API version: $api_version" >&2
  exit 1
fi

# If both fields are present but null/empty, the scan found no vulnerabilities — clean pass.
libs_count=$(jq '.result.libraries | if . == null then 0 else length end' "$INPUT_FILE" 2>/dev/null || echo 0)
eol_count=$(jq '.result.endOfLifeTechnologies | if . == null then 0 else length end' "$INPUT_FILE" 2>/dev/null || echo 0)
if [[ "$libs_count" -eq 0 && "$eol_count" -eq 0 ]]; then
  echo "No vulnerabilities found — image scan passed clean. Nothing to fix." >&2
  exit 0
fi

# ── parsed-vulns.txt ─────────────────────────────────────────────────────────
# Format: PACKAGE\tVERSION\tFIX_VERSION\tSEVERITY\tCVE_ID
# Extract findings from both Libraries and endOfLifeTechnologies arrays.

jq -r '
  [
    (
      .result.libraries[]?
      | select(.vulnerabilities != null and (.vulnerabilities | length) > 0)
      | .name as $pkg
      | .version as $ver
      | .vulnerabilities[]?
      | select(.severity != null and .severity != "")
      | {
          package: $pkg,
          version: ($ver | ltrimstr("v")),
          fixed: (if (.fixedVersion != null and .fixedVersion != "") then (.fixedVersion | ltrimstr("v")) else "NONE" end),
          severity: (.severity | ascii_upcase),
          cve: (.name // "UNKNOWN")
        }
    ),
    (
      .result.endOfLifeTechnologies[]?
      | select(.vulnerabilities != null and (.vulnerabilities | length) > 0)
      | .name as $pkg
      | .version as $ver
      | .vulnerabilities[]?
      | select(.severity != null and .severity != "")
      | {
          package: $pkg,
          version: ($ver | ltrimstr("v")),
          fixed: "NONE",
          severity: (.severity | ascii_upcase),
          cve: (.name // "EOL-TECHNOLOGY")
        }
    )
  ]
  | .[]
  | [.package, .version, .fixed, .severity, .cve]
  | @tsv
' "$INPUT_FILE" | sort -u > "$PARSED_FILE"

TOTAL=$(wc -l < "$PARSED_FILE" | tr -d ' ')
echo "Parsed $TOTAL vulnerability records from Wiz JSON into $PARSED_FILE"

if [[ "$TOTAL" -eq 0 ]]; then
  echo "No vulnerabilities found in $INPUT_FILE"
  exit 0
fi

# ── cve-map.txt ───────────────────────────────────────────────────────────────
# Format: PACKAGE\tCVE1, CVE2, ...
awk -F'\t' '
  NF >= 5 && $1 != "" && $5 != "" && !seen[$1 SUBSEP $5]++ {
    if (list[$1] != "") list[$1] = list[$1] ", " $5
    else list[$1] = $5
  }
  END {
    for (pkg in list) print pkg "\t" list[pkg]
  }
' "$PARSED_FILE" | sort > "$CVE_MAP_FILE"

# ── cve-version-map.txt ───────────────────────────────────────────────────────
# Format: PACKAGE@FIXVERSION\tCVE1, CVE2, ...  (fixable entries only)
awk -F'\t' '
  NF >= 5 && $3 != "" && $3 != "NONE" {
    key = $1 "@" $3
    cve = $5
    if (key != "" && cve != "" && !seen[key SUBSEP cve]++) {
      if (list[key] != "") list[key] = list[key] ", " cve
      else list[key] = cve
    }
  }
  END {
    for (key in list) print key "\t" list[key]
  }
' "$PARSED_FILE" | sort > "$CVE_VERSION_MAP_FILE"

echo "CVE maps written: $CVE_MAP_FILE, $CVE_VERSION_MAP_FILE"
