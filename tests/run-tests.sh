#!/usr/bin/env bash
#
# run-tests.sh — the checks that matter for this package.
#
# No framework on purpose: the units under test are shell scripts whose whole
# contract is "given this TSV, write these JSON lines", so plain asserts on
# real invocations test the actual thing. Run from anywhere:
#
#   bash tests/run-tests.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPTS="$PKG_ROOT/scripts"

PASS=0
FAIL=0

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; FAIL=$((FAIL + 1)); }

assert_eq() {
  local desc="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then pass "$desc"; else fail "$desc" "want '$want', got '$got'"; fi
}

workdir() {
  local d
  d="$(mktemp -d)"
  echo "$d"
}

# ── decide.sh ────────────────────────────────────────────────────────────────
#
# The predecessor (risk-score.sh) put EVERY finding in auto_apply: at the
# shipped weights the worst realistic input scored 0.67 against an auto
# threshold of 0.85, so a major bump and a stdlib finding were both "safe to
# apply automatically". These cases pin the policy that replaced it.
echo "decide.sh — classification"

d="$(workdir)"
cd "$d" || exit 1
cat > parsed-vulns.txt <<'EOF'
github.com/a/patchpkg	v1.2.3	v1.2.9	HIGH	CVE-1
github.com/b/minorpkg	v1.2.0	v1.5.0	CRITICAL	CVE-2
github.com/c/bigminor	v1.2.0	v1.40.0	MEDIUM	CVE-3
github.com/d/majorpkg	v1.9.0	v2.0.0	CRITICAL	CVE-4
stdlib	v1.21.0	v1.21.5	HIGH	CVE-5
github.com/e/nofix	v0.1.0	NONE	CRITICAL	CVE-6
github.com/f/weird	not-a-version	v1.0.0	LOW	CVE-7
EOF

bash "$SCRIPTS/decide.sh" >/dev/null 2>&1

decision_for() {
  jq -r --arg p "$1" 'select(.package==$p) | .decision' risk-decisions.jsonl
}
bump_for() {
  jq -r --arg p "$1" 'select(.package==$p) | .bump_type' risk-decisions.jsonl
}

assert_eq "patch bump auto-applies"                 "auto_apply"      "$(decision_for github.com/a/patchpkg)"
assert_eq "minor bump within the cap auto-applies"  "auto_apply"      "$(decision_for github.com/b/minorpkg)"
assert_eq "minor bump beyond the cap needs review"  "review_required" "$(decision_for github.com/c/bigminor)"
assert_eq "major bump is never automatic"           "review_required" "$(decision_for github.com/d/majorpkg)"
assert_eq "stdlib is never automatic"               "review_required" "$(decision_for stdlib)"
assert_eq "unparseable version needs review"        "review_required" "$(decision_for github.com/f/weird)"
assert_eq "no published fix skips"                  "skip_auto"       "$(decision_for github.com/e/nofix)"
assert_eq "unparseable bump is labelled unknown"    "unknown"         "$(bump_for github.com/f/weird)"

# A CRITICAL severity must not make a fix LESS likely to apply. The old model
# added severity to a "risk" score and compared it against a skip threshold,
# so higher severity pushed toward skipping — backwards.
assert_eq "CRITICAL severity does not block a safe bump" \
  "auto_apply" "$(decision_for github.com/b/minorpkg)"

# Only auto_apply reaches the allowlist, and the allowlist is the only thing
# parse-fix.sh consults before `go mod edit`.
jq -r 'select(.decision=="auto_apply") | .package' risk-decisions.jsonl | sort > allow.txt
assert_eq "allowlist contains exactly the two safe bumps" \
  "github.com/a/patchpkg
github.com/b/minorpkg" "$(cat allow.txt)"

# Vulnerabilities with no fix used to be dropped from the decisions file
# entirely, so they never reached the review queue or the report-back.
assert_eq "no-fix findings are still reported" "1" \
  "$(jq -s '[.[] | select(.decision=="skip_auto")] | length' risk-decisions.jsonl)"

echo "decide.sh — policy is configurable"
bash "$SCRIPTS/decide.sh" --auto-apply patch --output patch-only.jsonl >/dev/null 2>&1
assert_eq "excluding minor from auto_apply demotes it to review" "review_required" \
  "$(jq -r 'select(.package=="github.com/b/minorpkg") | .decision' patch-only.jsonl)"

bash "$SCRIPTS/decide.sh" --max-minor-jump 50 --output wide.jsonl >/dev/null 2>&1
assert_eq "raising the cap promotes a large minor jump" "auto_apply" \
  "$(jq -r 'select(.package=="github.com/c/bigminor") | .decision' wide.jsonl)"

echo "decide.sh — legacy flags"
# An existing config passes thresholds and weights. They must be accepted and
# ignored, not crash the run.
if bash "$SCRIPTS/decide.sh" --mode heuristic --auto-threshold 0.85 \
     --review-threshold 0.90 --min-confidence 0.70 --confidence 0.75 \
     --exploit-weight 0.40 --version-weight 0.35 --cycle-weight 0.25 \
     --metrics-file /nonexistent --output legacy.jsonl >/dev/null 2>&1; then
  assert_eq "legacy scoring flags are accepted and ignored" "auto_apply" \
    "$(jq -r 'select(.package=="github.com/a/patchpkg") | .decision' legacy.jsonl)"
else
  fail "legacy scoring flags are accepted and ignored" "decide.sh exited non-zero"
fi

# Bad policy must fail loudly rather than silently defaulting.
if bash "$SCRIPTS/decide.sh" --max-minor-jump abc --output bad.jsonl >/dev/null 2>&1; then
  fail "non-numeric max-minor-jump is rejected" "exited 0"
else
  pass "non-numeric max-minor-jump is rejected"
fi
if bash "$SCRIPTS/decide.sh" --auto-apply major --output bad2.jsonl >/dev/null 2>&1; then
  fail "auto-applying 'major' is rejected" "exited 0"
else
  pass "auto-applying 'major' is rejected"
fi

cd / && rm -rf "$d"

# ── version-selector.sh ──────────────────────────────────────────────────────
#
# Regression: `reasons=()` was reset only inside the parseable branch, so an
# unparseable version appended onto the previous package's reasons and every
# later row inherited them.
echo "version-selector.sh — reasons do not leak between rows"

d="$(workdir)"
cd "$d" || exit 1
# Unparseable row FIRST, so a leak would contaminate the rows after it.
cat > parsed-vulns.txt <<'EOF'
github.com/x/broken	garbage	alsogarbage	HIGH	CVE-100
github.com/y/patch	v1.0.0	v1.0.1	HIGH	CVE-101
github.com/z/minor	v1.0.0	v1.3.0	HIGH	CVE-102
EOF

bash "$SCRIPTS/version-selector.sh" parsed-vulns.txt recs.jsonl >/dev/null 2>&1

assert_eq "a patch row carries only patch_only" "patch_only" \
  "$(jq -r 'select(.package=="github.com/y/patch") | .reasons | join(",")' recs.jsonl)"
assert_eq "a minor row carries only minor_version_change" "minor_version_change" \
  "$(jq -r 'select(.package=="github.com/z/minor") | .reasons | join(",")' recs.jsonl)"
assert_eq "the unparseable row carries only its own reason" "unparseable_version" \
  "$(jq -r 'select(.package=="github.com/x/broken") | .reasons | join(",")' recs.jsonl)"

cd / && rm -rf "$d"

# ── fetch-config.sh ──────────────────────────────────────────────────────────
echo "fetch-config.sh — fallback behaviour"

d="$(workdir)"
cd "$d" || exit 1
cat > snapshot.yaml <<'EOF'
global:
  harbor_registry: "harbor.example.com"
services:
  my-service:
    team: my-team
    image_name: my-service
    dockerfile_path: docker/Dockerfile
    server_build_path: ./cmd/server
    base_image: "harbor.example.com/base:v1"
    go_private: "github.com/Example-CTO/*"
EOF

if command -v yq >/dev/null 2>&1; then
  # No API configured -> snapshot, and it must say so loudly.
  out=$(CONFIG_API_URL="" bash "$SCRIPTS/fetch-config.sh" \
          --service my-service --fallback snapshot.yaml --out resolved.yaml 2>&1)
  if grep -q "::warning::" <<<"$out"; then
    pass "falling back to the snapshot emits a warning"
  else
    fail "falling back to the snapshot emits a warning" "no ::warning:: in output"
  fi
  assert_eq "the snapshot is used verbatim" "my-team" \
    "$(yq eval '.services["my-service"].team' resolved.yaml)"

  # An unreachable API must fall back, not fail the run.
  if CONFIG_API_URL="http://127.0.0.1:1" bash "$SCRIPTS/fetch-config.sh" \
       --service my-service --fallback snapshot.yaml --out r2.yaml >/dev/null 2>&1; then
    pass "an unreachable API falls back instead of failing"
  else
    fail "an unreachable API falls back instead of failing" "exited non-zero"
  fi

  # A service missing everywhere must fail — running with no config would scan
  # the wrong thing or nothing at all.
  if bash "$SCRIPTS/fetch-config.sh" --service nope --fallback snapshot.yaml \
       --out r3.yaml >/dev/null 2>&1; then
    fail "an unknown service is rejected" "exited 0"
  else
    pass "an unknown service is rejected"
  fi
else
  echo "  SKIP fetch-config.sh tests (yq not installed)"
fi

cd / && rm -rf "$d"

# ── summary ──────────────────────────────────────────────────────────────────
echo
echo "─────────────────────────────"
printf 'passed: %d   failed: %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
