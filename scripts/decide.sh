#!/usr/bin/env bash
# Compatible with bash and zsh. When invoked via `zsh script.sh`, emulate bash
# to normalise array indexing, word splitting, and option behaviour.
[ -n "$ZSH_VERSION" ] && emulate bash
set -euo pipefail

# decide.sh — classify each fixable vulnerability as auto-apply, review, or skip.
#
# Replaces risk-score.sh, which computed a weighted "risk score" that could not
# actually discriminate. With the shipped weights (0.40/0.35/0.25 summing to
# 1.0) the worst realistic input — CRITICAL severity with a patch-only bump —
# scored 0.67 against an auto-apply threshold of 0.85, so EVERY finding came
# out `auto_apply` and `skip_auto` was unreachable. `confidence` was a config
# constant (0.75) always above `min_confidence` (0.70), so that gate could
# never bind either. All 105 registered services carried identical values.
#
# The model was also backwards: a higher severity raised risk_score, which
# pushed a finding toward being SKIPPED — the opposite of what you want.
#
# What actually protected people was the version-jump guard in parse-fix.sh
# (SKIP_MAJOR_JUMP, SKIP_MINOR_JUMP_THRESHOLD). So this script encodes that
# real policy directly, where it can be read and tested:
#
#   patch bump                        -> auto_apply
#   minor bump within max_minor_jump  -> auto_apply
#   minor bump beyond the cap         -> review_required
#   major bump                        -> review_required   (never automatic)
#   Go stdlib                         -> review_required   (needs a toolchain bump)
#   unparseable versions              -> review_required   (cannot classify safely)
#   no published fix                  -> skip_auto
#
# Input:  parsed-vulns.txt, version-recommendations.jsonl
# Output: risk-decisions.jsonl  (one JSON object per package+fix pair)
#
# The legacy scoring flags are still accepted so an existing config keeps
# working; they are ignored with one deprecation warning.

INPUT="parsed-vulns.txt"
RECOMMENDATIONS="version-recommendations.jsonl"
OUTPUT="risk-decisions.jsonl"

# Policy. Defaults mirror the behaviour that was actually in force.
AUTO_APPLY="patch,minor"
MAX_MINOR_JUMP="20"
NEVER="major,stdlib"

RECOMMENDATIONS_INDEX=""
LEGACY_FLAGS_SEEN=0

usage() {
  cat <<'EOF'
Usage:
  decide.sh [options]

Policy options:
  --auto-apply <list>       Bump types eligible for automatic application.
                            Comma-separated subset of: patch,minor
                            (default: patch,minor)
  --max-minor-jump <int>    Largest minor-version delta still auto-applied
                            (default: 20)
  --never <list>            Bump types never applied automatically.
                            Comma-separated subset of: major,stdlib
                            (default: major,stdlib)

I/O options:
  --input <file>            Parsed vulns (default: parsed-vulns.txt)
  --recommendations <file>  Version recommendations (default: version-recommendations.jsonl)
  --output <file>           Decisions (default: risk-decisions.jsonl)
  -h, --help

Deprecated (accepted, ignored):
  --mode --auto-threshold --review-threshold --min-confidence --confidence
  --exploit-weight --version-weight --cycle-weight --metrics-file
    The weighted risk model these configured could not discriminate; see the
    comment at the top of this script.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) INPUT="${2:-}"; shift 2 ;;
    --recommendations) RECOMMENDATIONS="${2:-}"; shift 2 ;;
    --output) OUTPUT="${2:-}"; shift 2 ;;
    --auto-apply) AUTO_APPLY="${2:-}"; shift 2 ;;
    --max-minor-jump) MAX_MINOR_JUMP="${2:-}"; shift 2 ;;
    --never) NEVER="${2:-}"; shift 2 ;;
    # Legacy scoring knobs — consume the value and move on.
    --mode|--auto-threshold|--review-threshold|--min-confidence|--confidence|\
    --exploit-weight|--version-weight|--cycle-weight|--metrics-file)
      LEGACY_FLAGS_SEEN=1; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ "$LEGACY_FLAGS_SEEN" -eq 1 ]]; then
  echo "Notice: risk-scoring flags (thresholds/weights/confidence) are deprecated and ignored." >&2
  echo "        Policy is now explicit: --auto-apply, --max-minor-jump, --never." >&2
fi

if [[ ! -f "$INPUT" ]]; then
  echo "Error: input not found: $INPUT" >&2
  exit 1
fi
if ! [[ "$MAX_MINOR_JUMP" =~ ^[0-9]+$ ]]; then
  echo "Error: --max-minor-jump must be a non-negative integer, got: $MAX_MINOR_JUMP" >&2
  exit 2
fi

: > "$OUTPUT"

TEMP_FILES=()
# `return 0` is load-bearing. With an empty TEMP_FILES the loop's last command
# is a failed `[[ -n "" ]]`, so cleanup returned 1 — and because this runs from
# an EXIT trap, that status became the SCRIPT's exit status. The result was a
# spurious failure whenever version-recommendations.jsonl was absent (no temp
# file to register), which is exactly the path a clean scan takes. Inherited
# from risk-score.sh, where it had the same effect.
cleanup() {
  local f
  for f in "${TEMP_FILES[@]:-}"; do
    [[ -n "$f" && -f "$f" ]] && rm -f "$f"
  done
  return 0
}
trap cleanup EXIT

# rank_sev maps grype/Wiz severity words to a 1-5 rank. Unknown ranks 0 so an
# unrecognised severity never reads as more urgent than it is.
rank_sev() {
  case "$1" in
    CRITICAL) echo 5 ;;
    HIGH) echo 4 ;;
    MEDIUM) echo 3 ;;
    LOW) echo 2 ;;
    INFO) echo 1 ;;
    *) echo 0 ;;
  esac
}

# contains <needle> <comma-list>
contains() {
  case ",$2," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

# Validate the policy here as well as in the caller. This script is runnable
# standalone, and silently accepting `--auto-apply major` would produce zero
# auto-applies with no explanation — the user would blame the tool, not the
# flag. Only patch and minor are ever eligible; major is never automatic.
validate_list() {
  local flag="$1" list="$2" allowed="$3" item
  for item in ${list//,/ }; do
    if ! contains "$item" "$allowed"; then
      echo "Error: $flag may only contain ${allowed//,/ or } — got '$item'" >&2
      exit 2
    fi
  done
}
validate_list "--auto-apply" "$AUTO_APPLY" "patch,minor"
validate_list "--never" "$NEVER" "major,stdlib"

AUTO_PATCH=0; AUTO_MINOR=0
contains patch "$AUTO_APPLY" && AUTO_PATCH=1
contains minor "$AUTO_APPLY" && AUTO_MINOR=1
NEVER_MAJOR=0; NEVER_STDLIB=0
contains major "$NEVER" && NEVER_MAJOR=1
contains stdlib "$NEVER" && NEVER_STDLIB=1

# version_safety is kept in the output because it is a real signal produced by
# version-selector.sh and is useful context in the review queue — unlike the
# scores this script no longer emits.
if [[ -f "$RECOMMENDATIONS" ]]; then
  RECOMMENDATIONS_INDEX="$(mktemp)"
  TEMP_FILES+=("$RECOMMENDATIONS_INDEX")
  jq -r 'select(.package != null and .recommended_version != null)
         | [.package, .recommended_version, (.safety_score // 0.50)] | @tsv' \
    "$RECOMMENDATIONS" 2>/dev/null > "$RECOMMENDATIONS_INDEX" || true
fi

get_version_safety() {
  local pkg="$1" fix_ver="$2" score
  [[ -n "$RECOMMENDATIONS_INDEX" && -s "$RECOMMENDATIONS_INDEX" ]] || { echo "0.50"; return; }
  score=$(awk -F'\t' -v p="$pkg" -v v="$fix_ver" '$1==p && $2==v {print $3; exit}' \
            "$RECOMMENDATIONS_INDEX" 2>/dev/null || true)
  [[ -z "$score" ]] && score="0.50"
  echo "$score"
}

# classify_bump <current> <fixed> -> "<type>\t<minor_delta>"
# type: patch | minor | major | unknown
classify_bump() {
  local cur="${1#v}" fix="${2#v}"
  # Strip pre-release and build metadata before comparing, same normalisation
  # version-selector.sh uses.
  cur="${cur%%-*}"; cur="${cur%%+*}"
  fix="${fix%%-*}"; fix="${fix%%+*}"

  local cma cmi cpa fma fmi fpa
  IFS='.' read -r cma cmi _ <<< "$cur"
  IFS='.' read -r fma fmi _ <<< "$fix"
  cma=${cma:-}; cmi=${cmi:-0}; fma=${fma:-}; fmi=${fmi:-0}

  if ! [[ "$cma" =~ ^[0-9]+$ ]] || ! [[ "$fma" =~ ^[0-9]+$ ]]; then
    printf 'unknown\t0'; return
  fi
  cmi=${cmi:-0}; fmi=${fmi:-0}
  [[ "$cmi" =~ ^[0-9]+$ ]] || cmi=0
  [[ "$fmi" =~ ^[0-9]+$ ]] || fmi=0

  if [[ "$fma" -ne "$cma" ]]; then
    printf 'major\t0'
  elif [[ "$fmi" -ne "$cmi" ]]; then
    local delta=$(( fmi > cmi ? fmi - cmi : cmi - fmi ))
    printf 'minor\t%d' "$delta"
  else
    printf 'patch\t0'
  fi
}

# Aggregate by package + current + fixed version, carrying the worst severity
# and a distinct CVE count. Rows with no published fix ($3 == "NONE") are
# excluded here — parse-fix.sh routes those into its manual-remediation
# section — so they are re-emitted below as skip_auto for completeness.
awk -F'\t' '
  $1!="" && $3!="" && $3!="NONE" {
    key=$1 "\t" $2 "\t" $3
    sev_rank=($4=="CRITICAL"?5:($4=="HIGH"?4:($4=="MEDIUM"?3:($4=="LOW"?2:($4=="INFO"?1:0)))))
    if (sev_rank > max_sev[key]) { max_sev[key]=sev_rank; max_sev_txt[key]=$4 }
    if ($5 != "") {
      cve_key=key SUBSEP $5
      if (!seen_cve[cve_key]++) cve_count[key]++
    }
  }
  END {
    for (k in max_sev) {
      split(k, a, "\t")
      c=(k in cve_count ? cve_count[k] : 0)
      print a[1] "\t" a[2] "\t" a[3] "\t" max_sev_txt[k] "\t" c
    }
  }
' "$INPUT" | sort -u | while IFS=$'\t' read -r pkg cur fix sev cvecount; do

  sev_rank=$(rank_sev "$sev")
  exploit_score=$(awk -v s="$sev_rank" 'BEGIN{printf "%.2f", s/5.0}')
  version_safety=$(get_version_safety "$pkg" "$fix")

  IFS=$'\t' read -r bump minor_delta <<< "$(classify_bump "$cur" "$fix")"

  reasons=()
  decision="review_required"

  if [[ "$pkg" == "stdlib" ]] && [[ "$NEVER_STDLIB" -eq 1 ]]; then
    # A stdlib finding needs the Go toolchain bumped, not a module edit.
    # parse-fix.sh reports it separately and never applies it.
    decision="review_required"
    reasons+=("stdlib_requires_toolchain_bump")
  else
    case "$bump" in
      patch)
        if [[ "$AUTO_PATCH" -eq 1 ]]; then
          decision="auto_apply"; reasons+=("patch_bump")
        else
          decision="review_required"; reasons+=("patch_not_in_auto_apply")
        fi
        ;;
      minor)
        if [[ "$AUTO_MINOR" -eq 0 ]]; then
          decision="review_required"; reasons+=("minor_not_in_auto_apply")
        elif [[ "$minor_delta" -gt "$MAX_MINOR_JUMP" ]]; then
          decision="review_required"
          reasons+=("minor_jump_${minor_delta}_exceeds_${MAX_MINOR_JUMP}")
        else
          decision="auto_apply"; reasons+=("minor_bump_${minor_delta}")
        fi
        ;;
      major)
        decision="review_required"
        if [[ "$NEVER_MAJOR" -eq 1 ]]; then
          reasons+=("major_bump_never_automatic")
        else
          reasons+=("major_bump")
        fi
        ;;
      *)
        decision="review_required"
        reasons+=("unparseable_version")
        ;;
    esac
  fi

  # Context, not decisive — but it is what a reviewer triages by.
  [[ "$sev" == "CRITICAL" ]] && reasons+=("severity=CRITICAL")
  [[ "${cvecount:-0}" -ge 3 ]] && reasons+=("cve_count=${cvecount}")

  reasons_json=$(printf "%s\n" "${reasons[@]}" | awk 'NF{printf "\"%s\",",$0}' | sed 's/,$//')
  [[ -z "$reasons_json" ]] && reasons_json="\"baseline\""

  printf '{"package":"%s","current_version":"%s","fixed_version":"%s","severity_max":"%s","cve_count":%s,"bump_type":"%s","minor_delta":%s,"exploit_score":%s,"version_safety":%s,"decision":"%s","reasons":[%s]}\n' \
    "$pkg" "$cur" "$fix" "$sev" "${cvecount:-0}" "$bump" "${minor_delta:-0}" \
    "$exploit_score" "$version_safety" "$decision" "$reasons_json" >> "$OUTPUT"
done

# Vulnerabilities with no published fix. The old script dropped these entirely,
# so they never reached the review queue and were visible only in parse-fix's
# markdown. Emitting them as skip_auto means the report-back to CVE Fix sees
# them too — they are precisely the ones a human or the AI fixer must handle.
awk -F'\t' '
  $1!="" && ($3=="NONE" || $3=="") {
    key=$1 "\t" $2
    sev_rank=($4=="CRITICAL"?5:($4=="HIGH"?4:($4=="MEDIUM"?3:($4=="LOW"?2:($4=="INFO"?1:0)))))
    if (sev_rank > max_sev[key]) { max_sev[key]=sev_rank; max_sev_txt[key]=$4 }
    if ($5 != "") {
      cve_key=key SUBSEP $5
      if (!seen_cve[cve_key]++) cve_count[key]++
    }
  }
  END {
    for (k in max_sev) {
      split(k, a, "\t")
      c=(k in cve_count ? cve_count[k] : 0)
      print a[1] "\t" a[2] "\t" max_sev_txt[k] "\t" c
    }
  }
' "$INPUT" | sort -u | while IFS=$'\t' read -r pkg cur sev cvecount; do
  sev_rank=$(rank_sev "$sev")
  exploit_score=$(awk -v s="$sev_rank" 'BEGIN{printf "%.2f", s/5.0}')
  reasons_json='"no_published_fix"'
  [[ "$sev" == "CRITICAL" ]] && reasons_json="$reasons_json,\"severity=CRITICAL\""
  printf '{"package":"%s","current_version":"%s","fixed_version":"NONE","severity_max":"%s","cve_count":%s,"bump_type":"none","minor_delta":0,"exploit_score":%s,"version_safety":0.00,"decision":"skip_auto","reasons":[%s]}\n' \
    "$pkg" "$cur" "$sev" "${cvecount:-0}" "$exploit_score" "$reasons_json" >> "$OUTPUT"
done

echo "Wrote $OUTPUT ($(wc -l < "$OUTPUT" | tr -d ' ') decisions)"
