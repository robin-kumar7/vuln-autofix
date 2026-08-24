#!/usr/bin/env bash
# Compatible with bash and zsh. When invoked via `zsh script.sh`, emulate bash
# to normalise array indexing, word splitting, and option behaviour.
[ -n "$ZSH_VERSION" ] && emulate bash
set -euo pipefail

# Load threshold configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config/thresholds.env"

# Recommend safest-scored fix version among candidates (Job #3)
# Input: parsed-vulns.txt (pkg, cur_ver, fix_ver, sev, cve)
# Output: version-recommendations.jsonl (JSONL; one row per package+candidate fix version)
# Fields: package, current_version, recommended_version, safety_score, reasons[]

INPUT="${1:-parsed-vulns.txt}"
OUTPUT="${2:-version-recommendations.jsonl}"

if [[ ! -f "$INPUT" ]]; then
  echo "Input file not found: $INPUT" >&2
  exit 1
fi

# MEDIUM FIX #10: Check if input file is empty
if [[ ! -s "$INPUT" ]]; then
  echo "Input file is empty: $INPUT" >&2
  exit 1
fi

: > "$OUTPUT"

# Aggregate by package to find all candidate fix versions
awk -F'\t' '$3!="NONE" && $3!="" {
  pkg=$1
  cur=$2
  fix=$3
  key=pkg "\t" fix
  candidates[key]=1
  current_ver[pkg]=cur
}
END {
  for (k in candidates) {
    split(k, a, "\t")
    print a[1] "\t" a[2]
  }
}' "$INPUT" | sort -u | while IFS=$'\t' read -r pkg fix_ver; do
  
  cur_ver=$(awk -F'\t' -v p="$pkg" '$1==p {print $2; exit}' "$INPUT")
  
  # Parse versions: v1.2.3 or v1.0.0-rc1 -> major.minor.patch (strip pre-release info)
  cur_norm="${cur_ver#v}"
  fix_norm="${fix_ver#v}"
  # MEDIUM FIX #7: Remove both pre-release AND build metadata for comparison
  cur_norm="${cur_norm%%-*}"  # Remove -rc1, -alpha, etc.
  cur_norm="${cur_norm%%+*}"  # Remove +build.123, etc.
  fix_norm="${fix_norm%%-*}"
  fix_norm="${fix_norm%%+*}"
  
  cur_major=0
  cur_minor=0
  cur_patch=0
  fix_major=0
  fix_minor=0
  fix_patch=0
  IFS='.' read -r cur_major cur_minor cur_patch <<< "$cur_norm"
  IFS='.' read -r fix_major fix_minor fix_patch <<< "$fix_norm"

  # Reset per iteration, BEFORE the branch. This used to live only inside the
  # else, so an unparseable version appended "unparseable_version" onto
  # whatever the previous package had accumulated — every subsequent row
  # inherited stale reasons. The while loop shares one shell, so the array
  # persists across iterations unless cleared here.
  reasons=()

  # Validate parsing succeeded (handle invalid versions gracefully)
  if ! [[ "$cur_major" =~ ^[0-9]+$ ]] || ! [[ "$fix_major" =~ ^[0-9]+$ ]]; then
    echo "Warning: Could not parse versions for $pkg: $cur_ver -> $fix_ver" >&2
    safety_score="$VERSION_SAFETY_UNPARSEABLE"
    reasons+=("unparseable_version")
  else
    cur_major=${cur_major:-0}
    cur_minor=${cur_minor:-0}
    cur_patch=${cur_patch:-0}
    fix_major=${fix_major:-0}
    fix_minor=${fix_minor:-0}
    fix_patch=${fix_patch:-0}
    
    # Major version bump (high risk)
    if [[ "$fix_major" != "$cur_major" ]]; then
      safety_score=$(awk -v v="$VERSION_SAFETY_MAJOR" 'BEGIN{printf "%.2f", v}')
      reasons+=("major_version_change")
    # Minor version bump (medium risk)
    elif [[ "$fix_minor" != "$cur_minor" ]]; then
      safety_score=$(awk -v v="$VERSION_SAFETY_MINOR" 'BEGIN{printf "%.2f", v}')
      reasons+=("minor_version_change")
    # Patch-only (low risk)
    else
      safety_score=$(awk -v v="$VERSION_SAFETY_PATCH" 'BEGIN{printf "%.2f", v}')
      reasons+=("patch_only")
    fi
  fi
  
  # Build reasons JSON array
  reasons_json=$(printf "%s\n" "${reasons[@]}" | awk 'NF{printf "\"%s\",",$0}' | sed 's/,$//')
  [[ -z "$reasons_json" ]] && reasons_json="\"baseline\""
  
  printf '{"package":"%s","current_version":"%s","recommended_version":"%s","safety_score":%s,"reasons":[%s]}\n' \
    "$pkg" "$cur_ver" "$fix_ver" "$safety_score" "$reasons_json" >> "$OUTPUT"
done

echo "Wrote $OUTPUT"
