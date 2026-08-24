#!/usr/bin/env bash
#
# lint-config.sh — validate a services config against config/schema.json.
#
# The predecessor had no schema and no lint. A typo'd key or a missing required
# field surfaced at run time, inside scan-and-fix.sh, AFTER the Docker build —
# so onboarding a service wrong cost a full CI cycle to discover. This runs in
# CI on every change to the config, and analytics-api runs the same checks
# before saving a wizard registration.
#
#   bash scripts/lint-config.sh config/services-config.yaml
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA="${SCRIPT_DIR}/../config/schema.json"
TARGET="${1:-${SCRIPT_DIR}/../config/services-config.yaml}"

[[ -f "$TARGET" ]] || { echo "Error: config not found: $TARGET" >&2; exit 1; }
[[ -f "$SCHEMA" ]] || { echo "Error: schema not found: $SCHEMA" >&2; exit 1; }

# Prefer a real JSON Schema validator; fall back to a structural check so CI
# still catches the common mistakes on a runner without jsonschema installed.
if python3 -c 'import jsonschema, yaml' 2>/dev/null; then
  python3 - "$SCHEMA" "$TARGET" <<'PY'
import json, sys, yaml, jsonschema

schema_path, target_path = sys.argv[1], sys.argv[2]
schema = json.load(open(schema_path))
cfg = yaml.safe_load(open(target_path))

validator = jsonschema.Draft202012Validator(schema)
errors = sorted(validator.iter_errors(cfg), key=lambda e: list(e.path))

services = (cfg or {}).get("services") or {}
print(f"Validating {len(services)} service(s) in {target_path}")

if not errors:
    print("OK: config matches the schema")
    sys.exit(0)

for e in errors:
    where = "/".join(str(p) for p in e.path) or "<root>"
    print(f"  FAIL {where}: {e.message}")
print(f"\n{len(errors)} schema violation(s)")
sys.exit(1)
PY
  exit $?
fi

echo "Note: python jsonschema not available; running the structural fallback check" >&2

python3 - "$SCHEMA" "$TARGET" <<'PY'
import json, re, sys
try:
    import yaml
except ImportError:
    print("Error: pyyaml is required to lint the config", file=sys.stderr)
    sys.exit(1)

schema_path, target_path = sys.argv[1], sys.argv[2]
schema = json.load(open(schema_path))
svc_schema = schema["$defs"]["service"]
allowed = set(svc_schema["properties"])
required = set(svc_schema["required"])
build_path_re = re.compile(svc_schema["properties"]["server_build_path"]["pattern"])

cfg = yaml.safe_load(open(target_path)) or {}
if "services" not in cfg:
    print("  FAIL <root>: missing required 'services' section")
    sys.exit(1)

services = cfg["services"] or {}
print(f"Validating {len(services)} service(s) in {target_path}")

failures = []
for name, svc in services.items():
    if not isinstance(svc, dict):
        failures.append(f"services/{name}: expected a mapping")
        continue
    for key in sorted(set(svc) - allowed):
        # The most valuable check: a typo'd key was previously silent, and the
        # field it was meant to set just took its default.
        failures.append(f"services/{name}: unknown field '{key}'")
    for key in sorted(required - set(svc)):
        failures.append(f"services/{name}: missing required field '{key}'")
    sbp = svc.get("server_build_path")
    if sbp and not build_path_re.match(str(sbp)):
        failures.append(f"services/{name}: server_build_path '{sbp}' must start with '.'")

for f in failures:
    print(f"  FAIL {f}")
if failures:
    print(f"\n{len(failures)} problem(s)")
    sys.exit(1)
print("OK: config is structurally valid")
PY
