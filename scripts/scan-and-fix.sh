#!/usr/bin/env bash
# Central vulnerability scan and auto-fix orchestrator
# Reads service configuration from centralized YAML and executes the full
# vulnerability remediation pipeline: scan, parse, recommend, score, apply, validate.
#
# Compatible with bash and zsh. When invoked via `zsh script.sh`, emulate bash
# to normalise array indexing, word splitting, and option behaviour.
[ -n "$ZSH_VERSION" ] && emulate bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/../config/thresholds.env"
REPO_ROOT="${REPO_ROOT:-.}"
SERVICE_NAME=""
CONFIG_FILE=""
DRY_RUN=false
SCAN_SKIPPED_REASON=""
SCAN_MODE=""
BUILD_VALIDATION_STATUS="skipped"

# ──────────────────────────────────────────────────────────────────────────────
# USAGE
# ──────────────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Usage: $(basename "$0") --service SERVICE_NAME --config CONFIG_FILE [options]

Required:
  --service SERVICE_NAME      Name of service to scan (e.g., ddi-dispatcher)
  --config CONFIG_FILE        Path to services-config.yaml

Options:
  --repo-root REPO_ROOT       Repository root directory (default: current directory)
  --dry-run                   Show what would be done without making changes
  -h, --help                  Show this help message

Environment Variables:
  WIZ_CLIENT_ID               Wiz authentication (optional, uses cached token if set)
  WIZ_CLIENT_SECRET           Wiz authentication (optional)
  HARBOR_SERVICES_PROD_USERNAME   Harbor registry auth (optional)
  HARBOR_SERVICES_PROD_PASSWORD   Harbor registry auth (optional)
  GITPAT                      GitHub token for private modules (optional)

Output Artifacts (in repo root):
  parsed-vulns.txt            Parsed vulnerability findings
  version-recommendations.jsonl   Recommended fix versions
  risk-decisions.jsonl        Risk scoring decisions
  allowlist.txt               Auto-applicable fixes
  vuln-fix-summary.md         PR-ready summary
  wiz-scan-results.json       Raw Wiz output (if Wiz used)
  grype-scan-output.json      Raw Grype output (if Grype used)
EOF
  exit "${1:-0}"
}

# ──────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ──────────────────────────────────────────────────────────────────────────────

while [[ $# -gt 0 ]]; do
  case "$1" in
    --service)    SERVICE_NAME="${2:-}"; shift 2 ;;
    --config)     CONFIG_FILE="${2:-}"; shift 2 ;;
    --repo-root)  REPO_ROOT="${2:-}"; shift 2 ;;
    --dry-run)    DRY_RUN=true; shift ;;
    -h|--help)    usage 0 ;;
    *)
      echo "Error: Unknown option '$1'" >&2
      usage 1
      ;;
  esac
done

[[ -z "$SERVICE_NAME" ]] && { echo "Error: --service is required" >&2; usage 1; }
[[ -z "$CONFIG_FILE" ]] && { echo "Error: --config is required" >&2; usage 1; }
[[ ! -f "$CONFIG_FILE" ]] && { echo "Error: Config file not found: $CONFIG_FILE" >&2; usage 1; }

# ──────────────────────────────────────────────────────────────────────────────
# LOAD CONFIGURATION (Global + Service)
# ──────────────────────────────────────────────────────────────────────────────

# Validate input configuration parameters
validate_config() {
  # Validates the remediation policy. The predecessor validated MODE and three
  # risk thresholds instead — inputs to a weighted score that could not
  # discriminate (see scripts/decide.sh). Legacy MODE/threshold/weight fields
  # are now simply ignored, so a stale config still runs.
  local auto_apply="${POLICY_AUTO_APPLY:-patch,minor}"
  local max_minor="${POLICY_MAX_MINOR_JUMP:-${SKIP_MINOR_JUMP_THRESHOLD:-20}}"
  local never="${POLICY_NEVER:-major,stdlib}"

  local item
  for item in ${auto_apply//,/ }; do
    case "$item" in
      patch|minor) ;;
      *) echo "Error: policy.auto_apply may only contain patch,minor — got '$item'" >&2; return 1 ;;
    esac
  done
  for item in ${never//,/ }; do
    case "$item" in
      major|stdlib) ;;
      *) echo "Error: policy.never may only contain major,stdlib — got '$item'" >&2; return 1 ;;
    esac
  done
  if ! [[ "$max_minor" =~ ^[0-9]+$ ]]; then
    echo "Error: policy.max_minor_jump must be a non-negative integer, got: $max_minor" >&2
    return 1
  fi
  return 0
}

# Check required commands are available
check_required_commands() {
  local required=(yq jq awk sed grep go docker)
  for cmd in "${required[@]}"; do
    if ! command -v "$cmd" &>/dev/null; then
      echo "Error: Required command not found: $cmd" >&2
      return 1
    fi
  done
  return 0
}

load_configuration() {
  local service="$1" config_file="$2"
  
  if [[ ! -f "$config_file" ]]; then
    echo "Error: Config file not found: $config_file" >&2
    exit 1
  fi
  
  # HIGH FIX #4: Validate YAML structure upfront
  if ! yq eval '.services' "$config_file" &>/dev/null; then
    echo "Error: Config file missing .services section" >&2
    echo "  Available top-level keys: $(yq eval 'keys | join(", ")' "$config_file" 2>/dev/null || echo "unknown")" >&2
    exit 1
  fi
  
  # Check all required commands upfront
  check_required_commands || exit 1
  
  # Load global settings with defaults
  log_info "Loading global settings from config"
  WIZ_CLI_VERSION="${WIZ_CLI_VERSION:-$(yq eval '.global.wiz_cli_version // "latest"' "$config_file" 2>/dev/null)}"
  HARBOR_REGISTRY="${HARBOR_REGISTRY:-$(yq eval '.global.harbor_registry // "harbor.services.sdp.infoblox.com"' "$config_file" 2>/dev/null)}"
  ARTIFACT_RETENTION_DAYS="${ARTIFACT_RETENTION_DAYS:-$(yq eval '.global.artifact_retention_days // 30' "$config_file" 2>/dev/null)}"
  
  export WIZ_CLI_VERSION HARBOR_REGISTRY ARTIFACT_RETENTION_DAYS
  
  log_success "Global settings: WIZ_CLI_VERSION=$WIZ_CLI_VERSION, HARBOR_REGISTRY=$HARBOR_REGISTRY, ARTIFACT_RETENTION_DAYS=$ARTIFACT_RETENTION_DAYS"
  
  # Load service-specific settings
  log_info "Loading service configuration for: $service"
  if [[ "$(yq eval ".services[\"$service\"] == null" "$config_file" 2>/dev/null || echo true)" == "true" ]]; then
    echo "Error: Service '$service' not found in config" >&2
    exit 1
  fi

  # Export every top-level service key as an uppercase environment variable.
  # Example: image_name -> IMAGE_NAME, risk_threshold_auto -> RISK_THRESHOLD_AUTO
  local service_keys=()
  local key env_name value
  while IFS= read -r key; do
    service_keys+=("$key")
  done < <(yq eval ".services[\"$service\"] | keys | .[]" "$config_file" 2>/dev/null)

  if [[ ${#service_keys[@]} -eq 0 ]]; then
    echo "Error: Service '$service' has no configuration keys" >&2
    exit 1
  fi

  for key in "${service_keys[@]}"; do
    [[ -z "$key" || "$key" == "null" ]] && continue

    env_name="$(echo "$key" | tr '[:lower:]' '[:upper:]' | sed 's/[^A-Z0-9_]/_/g')"
    if [[ ! "$env_name" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
      env_name="SERVICE_${env_name}"
    fi

    value="$(yq eval ".services[\"$service\"].\"$key\" // \"\"" "$config_file" 2>/dev/null)"
    printf -v "$env_name" '%s' "$value"
    # shellcheck disable=SC2163  # exporting the variable NAMED BY env_name is
    # the intent: every config key becomes an env var, which is why adding a
    # config field needs no change here.
    export "$env_name"
  done
  
  # Validate required fields are set
  local required_fields=(IMAGE_NAME DOCKERFILE_PATH SERVER_BUILD_PATH BASE_IMAGE)
  for field in "${required_fields[@]}"; do
    if [[ -z "${!field:-}" ]]; then
      echo "Error: Missing required config field: $field for service $service" >&2
      exit 1
    fi
  done
  
  # Validate configuration values
  validate_config || exit 1
  
  log_success "Loaded service config: $service"
}

# ──────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

log_step() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "▶ $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

log_info() {
  echo "  ℹ $1"
}

log_success() {
  echo "  ✓ $1"
}

log_warn() {
  echo "  ⚠ $1" >&2
}

log_error() {
  echo "  ✗ $1" >&2
}

run_cmd() {
  local desc="$1"
  shift
  
  if [[ "$DRY_RUN" == true ]]; then
    log_info "[DRY-RUN] $desc"
    log_info "Command: $*"
    return 0
  fi
  
  log_info "$desc"
  if "$@"; then
    log_success "Completed"
  else
    log_error "Failed"
    return 1
  fi
}

append_step_summary() {
  local message="$1"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '%s\n' "$message" >> "$GITHUB_STEP_SUMMARY"
  fi
}

configure_git_auth_for_private_modules() {
  if [[ -n "${GITPAT:-}" ]]; then
    run_cmd "Configuring git auth for private modules" \
      git config --global url."https://${GITPAT}@github.com/".insteadOf "https://github.com/"
  else
    log_info "Skipping private module git auth; GITPAT not configured"
  fi
}

configure_go_module_access() {
  if [[ -n "${GO_PRIVATE:-}" ]]; then
    export GOPRIVATE="$GO_PRIVATE"
    export GONOSUMDB="$GO_PRIVATE"
    log_success "Configured GOPRIVATE and GONOSUMDB for $GO_PRIVATE"
    if [[ -n "${GITHUB_ENV:-}" ]]; then
      {
        echo "GOPRIVATE=$GO_PRIVATE"
        echo "GONOSUMDB=$GO_PRIVATE"
      } >> "$GITHUB_ENV"
    fi
  else
    log_info "GO_PRIVATE not set; using public module resolution only"
  fi

  export GOPROXY="https://proxy.golang.org,direct"
  log_success "Configured GOPROXY=$GOPROXY"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "GOPROXY=$GOPROXY" >> "$GITHUB_ENV"
  fi

  clear_go_vcs_cache
}

# Remove Go's VCS cache before any host `go` command. actions/setup-go restores
# the module cache (cache: true), including stale *shallow* git clones under
# pkg/mod/cache/vcs. When Go later resolves a private pseudo-version it runs
# `git fetch --unshallow` against that stale clone and fails with
# "fatal: shallow file has changed since we read it". Clearing only the VCS
# cache forces a fresh fetch; module downloads and extracted sources are kept.
clear_go_vcs_cache() {
  local gopath
  gopath="$(go env GOPATH 2>/dev/null || echo "${HOME}/go")"
  if [[ -n "$gopath" ]]; then
    run_cmd "Clearing Go VCS cache (avoids shallow-clone fetch errors)" \
      bash -c "rm -rf \"${gopath}/pkg/mod/cache/vcs\" 2>/dev/null || true"
  fi
}

login_harbor_registry() {
  if [[ -z "${HARBOR_REGISTRY:-}" && -z "${HARBOR_SERVICES_PROD_USERNAME:-}" && -z "${HARBOR_SERVICES_PROD_PASSWORD:-}" ]]; then
    log_info "Skipping Harbor login; registry and credentials not configured"
    return 0
  fi

  if [[ -n "${HARBOR_REGISTRY:-}" && -n "${HARBOR_SERVICES_PROD_USERNAME:-}" && -n "${HARBOR_SERVICES_PROD_PASSWORD:-}" ]]; then
    log_info "Logging in to Harbor registry $HARBOR_REGISTRY"
    if [[ "$DRY_RUN" == true ]]; then
      log_info "[DRY-RUN] Harbor login"
      return 0
    fi
    printf '%s' "$HARBOR_SERVICES_PROD_PASSWORD" | docker login "$HARBOR_REGISTRY" -u "$HARBOR_SERVICES_PROD_USERNAME" --password-stdin
    log_success "Harbor login completed"
    return 0
  fi

  log_error "Harbor login configuration is incomplete. Set HARBOR_REGISTRY, HARBOR_SERVICES_PROD_USERNAME, and HARBOR_SERVICES_PROD_PASSWORD together."
  return 1
}

build_review_queue() {
  : > review-queue.md

  if [[ ! -s "risk-decisions.jsonl" ]]; then
    log_info "No risk-decisions.jsonl file; skipping review queue section"
    return 0
  fi

  local total
  total=$(jq -s '[.[] | select(.decision=="review_required" or .decision=="skip_auto")] | length' risk-decisions.jsonl)
  if [[ "${total:-0}" -eq 0 ]]; then
    log_info "No review_required or skip_auto items; skipping review queue section"
    return 0
  fi

  local rows
  rows=$(jq -r '
    select(.decision=="review_required" or .decision=="skip_auto")
    | "| "
      + (.package|tostring|gsub("\\|";"\\\\|"))
      + " | "
      + ((.current_version + " -> " + .fixed_version)|tostring|gsub("\\|";"\\\\|"))
      + " | "
      + (.decision|tostring)
      + " | "
      + (.bump_type|tostring)
      + " | "
      + (.severity_max|tostring)
      + " | "
      + (((.reasons // [])[:2] | join("; "))|tostring|gsub("\\|";"\\\\|"))
      + " |"
  ' risk-decisions.jsonl | head -n 20)

  {
    echo "### Risk Review Queue"
    echo ""
    echo "| Package | Version Change | Decision | Bump | Severity | Reasons |"
    echo "|---|---|---|---|---|---|"
    echo "$rows"
    if [[ "$total" -gt 20 ]]; then
      echo ""
      echo "_Showing first 20 of $total items. See workflow artifact risk-decisions.jsonl for full list._"
    fi
  } > review-queue.md
}

write_skip_summary() {
  {
    echo "## Auto Vulnerability Fix Result"
    echo ""
    echo "$SCAN_SKIPPED_REASON"
    echo ""
    echo "No scan/remediation steps were executed in this run."
  } > vuln-fix-summary.md

  append_step_summary "## Auto Vulnerability Fix Result"
  append_step_summary ""
  append_step_summary "$SCAN_SKIPPED_REASON"
  append_step_summary ""
  append_step_summary "No scan/remediation steps were executed in this run."
}

determine_scan_mode() {
  if [[ -n "${WIZ_CLIENT_ID:-}" && -n "${WIZ_CLIENT_SECRET:-}" ]]; then
    SCAN_MODE="wiz"
    return 0
  fi

  if [[ "${ENABLE_GRYPE_FALLBACK:-false}" == "true" ]] && command -v grype &>/dev/null; then
    SCAN_MODE="grype"
    return 0
  fi

  SCAN_MODE="skip"
  SCAN_SKIPPED_REASON="Missing WIZ_CLIENT_ID/WIZ_CLIENT_SECRET; skipping Wiz auth and scan."
  write_skip_summary
  return 1
}

# ──────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ──────────────────────────────────────────────────────────────────────────────

main() {
  cd "$REPO_ROOT"
  
  # Verify repo structure
  [[ -f "go.mod" ]] || { log_error "go.mod not found in $REPO_ROOT"; exit 1; }
  [[ -f "$DOCKERFILE_PATH" ]] || { log_error "Dockerfile not found: $DOCKERFILE_PATH"; exit 1; }
  
  log_step "Initializing Vulnerability Scan Pipeline"
  log_info "Service: $SERVICE_NAME"
  log_info "Repository: $REPO_ROOT"
  log_info "Image: $IMAGE_NAME"
  log_info "Global Config: WIZ_CLI_VERSION=$WIZ_CLI_VERSION, HARBOR_REGISTRY=$HARBOR_REGISTRY, ARTIFACT_RETENTION_DAYS=$ARTIFACT_RETENTION_DAYS"

  log_step "Workflow Bootstrap"
  configure_git_auth_for_private_modules
  configure_go_module_access

  if ! determine_scan_mode; then
    log_warn "$SCAN_SKIPPED_REASON"
    generate_summary
    return 0
  fi
  
  # Step 1: Build binary
  log_step "Step 1: Build Binary"
  run_cmd "Building Go binary" \
    bash -c "mkdir -p bin && CGO_ENABLED=0 go build -v -tags \"${BUILD_TAGS:-}\" -trimpath -ldflags \"${BUILD_LDFLAGS:-}\" -o bin/server \"$SERVER_BUILD_PATH\""
  
  # Step 1.5: Vendor dependencies so the Docker build resolves private modules
  # without needing VCS/git credentials inside the container. Host git auth
  # (configure_git_auth_for_private_modules) lets `go mod vendor` fetch private
  # repos here; the vendored tree is then used inside `docker build`.
  #
  # Opt-in per service (vendor_for_docker: true). Only needed by services whose
  # Dockerfile compiles in-container; services that COPY a prebuilt bin/server
  # (SERVER_BINARY build-arg) never fetch modules in Docker and should leave it
  # off to avoid unnecessary work and vendor/ side effects on later steps.
  if [[ "${VENDOR_FOR_DOCKER:-false}" == "true" ]]; then
    log_step "Step 1.5: Vendor Dependencies for Docker Build"
    run_cmd "Vendoring dependencies" \
      bash -c "go mod vendor"
  fi

  # Step 2: Build Docker image
  # DOCKER_BUILD_CONTEXT lets a service point the build context somewhere other
  # than the current dir — e.g. ".." to build from the repo root when a module's
  # Dockerfile COPYs repo-root/sibling paths (multi-module monorepos). Defaults
  # to "." so single-module repos build from the module dir exactly as before.
  # The -f path stays relative to cwd, independent of the context.
  log_step "Step 2: Build Docker Image for Scanning"
  login_harbor_registry
  run_cmd "Building Docker image" \
    bash -c "docker build --progress=plain -f \"$DOCKERFILE_PATH\" --build-arg BASE_IMAGE=\"$BASE_IMAGE\" ${DOCKER_BUILD_EXTRA_ARGS:-} -t \"$IMAGE_NAME:scan\" \"${DOCKER_BUILD_CONTEXT:-.}\""
  
  # Step 3: Scan image
  log_step "Step 3: Scan Docker Image"
  scan_image
  if [[ "$SCAN_MODE" == "skip" ]]; then
    log_warn "$SCAN_SKIPPED_REASON"
    generate_summary
    return 0
  fi
  
  # Step 4: Parse vulnerabilities
  log_step "Step 4: Parse Vulnerability Findings"
  parse_vulnerabilities

  # Short-circuit: if no findings were parsed, skip remediation steps entirely
  if [[ ! -s "parsed-vulns.txt" ]]; then
    log_info "No vulnerabilities found — image is clean. Skipping remediation steps."
    BUILD_VALIDATION_STATUS="skipped"
    printf '%s\n' "$BUILD_VALIDATION_STATUS" > build-validation-status.txt
    generate_summary
    return 0
  fi

  # Step 5: Recommend versions
  log_step "Step 5: Recommend Safe Versions"
  run_cmd "Analyzing package versions" \
    bash "$SCRIPT_DIR/version-selector.sh" parsed-vulns.txt version-recommendations.jsonl
  
  # Step 6: Score risk
  log_step "Step 6: Score Fix Risk vs Exploit Urgency"
  score_risk
  build_review_queue
  
  # Step 7: Apply fixes
  log_step "Step 7: Apply Auto-Allowlisted Fixes"
  apply_fixes
  
  # Step 8: Validate build
  if ! git diff --quiet -- go.mod go.sum vendor; then
    log_step "Step 8: Validate Build After Fixes"
    # apply_fixes bumped go.mod/go.sum; whenever a vendor/ tree is present
    # (generated by Step 1.5 or committed in the repo), refresh it so the host
    # build — which auto-uses -mod=vendor when vendor/ exists — doesn't fail
    # with "inconsistent vendoring".
    if [[ -d vendor ]]; then
      run_cmd "Re-vendoring dependencies after fixes" \
        bash -c "go mod vendor"
    fi
    if run_cmd "Rebuilding binary to validate" \
      bash -c "mkdir -p bin && CGO_ENABLED=0 go build -v -tags \"${BUILD_TAGS:-}\" -trimpath -ldflags \"${BUILD_LDFLAGS:-}\" -o bin/server \"$SERVER_BUILD_PATH\""; then
      BUILD_VALIDATION_STATUS="passed"
    else
      BUILD_VALIDATION_STATUS="failed"
      # Never propose a PR carrying a bump that doesn't compile: roll back
      # go.mod/go.sum/vendor exactly like parse-fix.sh does when `go mod
      # tidy`/`vendor` itself fails, and fail the run so it surfaces in
      # Actions instead of a cosmetic "review before merging" PR badge that
      # can be merged into main by mistake.
      log_error "Post-fix build validation failed; reverting go.mod/go.sum/vendor changes"
      git checkout -- go.mod go.sum 2>/dev/null || true
      [[ -d vendor ]] && git checkout -- vendor/ 2>/dev/null || true
      printf '%s\n' "$BUILD_VALIDATION_STATUS" > build-validation-status.txt
      generate_summary
      exit 1
    fi
  else
    log_step "Step 8: Build Validation"
    log_info "No fixes applied; skipping rebuild validation"
    BUILD_VALIDATION_STATUS="skipped"
  fi
  printf '%s\n' "$BUILD_VALIDATION_STATUS" > build-validation-status.txt
  
  # Step 9: Summary
  log_step "Step 9: Remediation Summary"
  generate_summary
  
  log_step "Vulnerability Remediation Pipeline Complete"
  log_success "All artifacts generated in $REPO_ROOT"
}

scan_image() {
  if [[ "$SCAN_MODE" == "grype" ]]; then
    log_info "Wiz credentials not available; falling back to Grype"
    if [[ "$DRY_RUN" == true ]]; then
      log_info "[DRY-RUN] Scanning image with Grype"
      return 0
    fi
    log_info "Scanning image with Grype"
    run_cmd "Scanning image with Grype" \
      bash "$SCRIPT_DIR/grype-parse.sh" "$IMAGE_NAME:scan" \
        --parsed parsed-vulns.txt \
        --cve-map cve-map.txt \
        --cve-version-map cve-version-map.txt \
        --grype-output grype-scan-output.json
    return 0
  fi

  if [[ "$SCAN_MODE" != "wiz" ]]; then
    SCAN_MODE="skip"
    SCAN_SKIPPED_REASON="Missing WIZ_CLIENT_ID/WIZ_CLIENT_SECRET; skipping Wiz auth and scan."
    write_skip_summary
    return 0
  fi

  log_info "Using Wiz scanner - Version: $WIZ_CLI_VERSION"

  local wizcli_bin
  if command -v wizcli &>/dev/null; then
    wizcli_bin="$(command -v wizcli)"
    log_success "Found local wizcli installation at $wizcli_bin"
  else
    wizcli_bin="$(mktemp -d)/wizcli"
    local download_success=false
    local os_type
    local arch
    os_type="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    if [[ "$arch" == "x86_64" ]]; then
      arch="amd64"
    elif [[ "$arch" == "aarch64" ]]; then
      arch="arm64"
    fi

    local download_url="https://downloads.wiz.io/v1/wizcli/${WIZ_CLI_VERSION}/wizcli-${os_type}-${arch}"

    for attempt in $(seq 1 "$RETRY_ATTEMPTS"); do
      if run_cmd "Downloading wizcli for ${os_type}-${arch} (attempt $attempt/$RETRY_ATTEMPTS)" \
        bash -c "curl -sL --fail -o '$wizcli_bin' '$download_url' && chmod +x '$wizcli_bin'"; then
        download_success=true
        break
      elif [[ $attempt -lt "$RETRY_ATTEMPTS" ]]; then
        log_warn "Download attempt $attempt failed, retrying in $RETRY_DELAY_SECONDS seconds..."
        sleep "$RETRY_DELAY_SECONDS"
      fi
    done

    if [[ "$download_success" != true ]]; then
      log_error "Failed to download wizcli after $RETRY_ATTEMPTS attempts"
      return 1
    fi
  fi

  run_cmd "Authenticating with Wiz" \
    "$wizcli_bin" auth --id "$WIZ_CLIENT_ID" --secret "$WIZ_CLIENT_SECRET"

  if [[ "$DRY_RUN" == true ]]; then
    log_info "[DRY-RUN] Scanning image with Wiz"
    return 0
  fi

  log_info "Scanning image with Wiz"
  if "$wizcli_bin" docker scan -i "$IMAGE_NAME:scan" \
    -p "PSE: Vulnerability - Critical - Audit/Warn - All Projects" \
    -p "PSE: Vulnerability - High - Audit/Warn - All Projects" \
    --json-output-file wiz-scan-results.json \
    --file-hashes-scan 2>&1 | tee wiz-scan-raw.txt; then
    if [[ ! -s "wiz-scan-results.json" ]]; then
      log_error "Wiz scan produced empty JSON output"
      return 1
    fi
    log_success "Completed"
  else
    local scan_exit=$?
    log_error "Wiz scan command failed with exit code $scan_exit"
    return "$scan_exit"
  fi
}

parse_vulnerabilities() {
  if [[ "$DRY_RUN" == true ]]; then
    log_info "Dry-run mode: skipping parse step (no scan artifacts expected)"
    return 0
  fi

  if [[ -f "wiz-scan-results.json" ]]; then
    log_info "Parsing Wiz output"
    run_cmd "Parsing Wiz JSON" \
      bash "$SCRIPT_DIR/wiz-json-parse.sh" wiz-scan-results.json \
        --parsed parsed-vulns.txt \
        --cve-map cve-map.txt \
        --cve-version-map cve-version-map.txt
  elif [[ -f "grype-scan-output.json" ]]; then
    log_info "Grype output already parsed"
  else
    log_error "No scan output found"
    exit 1
  fi
}

score_risk() {
  # POLICY_* come from the service config's `policy:` block (dynamically
  # exported by load_configuration like every other key). Defaults reproduce
  # the behaviour that was actually in force before: patch and minor bumps
  # auto-apply, minor jumps beyond 20 and all major bumps go to review.
  run_cmd "Deciding which fixes to apply" \
    bash "$SCRIPT_DIR/decide.sh" \
      --input parsed-vulns.txt \
      --recommendations version-recommendations.jsonl \
      --output risk-decisions.jsonl \
      --auto-apply "${POLICY_AUTO_APPLY:-patch,minor}" \
      --max-minor-jump "${POLICY_MAX_MINOR_JUMP:-${SKIP_MINOR_JUMP_THRESHOLD:-20}}" \
      --never "${POLICY_NEVER:-major,stdlib}"
  
  # Extract allowlist
  if [[ -f "risk-decisions.jsonl" ]]; then
    jq -r 'select(.decision=="auto_apply") | "\(.package)\t\(.fixed_version)"' \
      risk-decisions.jsonl > allowlist.txt || true
  fi
}

apply_fixes() {
  run_cmd "Applying allowlisted fixes" \
    bash "$SCRIPT_DIR/parse-fix.sh" \
      --mode apply \
      --parsed parsed-vulns.txt \
      --recommendations version-recommendations.jsonl \
      --allowlist allowlist.txt \
      --summary vuln-fix-summary.md
}

generate_summary() {
  log_info "Summary artifacts:"
  for artifact in vuln-fix-summary.md review-queue.md parsed-vulns.txt version-recommendations.jsonl risk-decisions.jsonl allowlist.txt wiz-scan-results.json wiz-scan-raw.txt cve-map.txt cve-version-map.txt build-validation-status.txt; do
    if [[ -f "$artifact" ]]; then
      local size=$(du -h "$artifact" | cut -f1)
      log_success "$artifact ($size)"
    fi
  done
}

# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

load_configuration "$SERVICE_NAME" "$CONFIG_FILE"
main
