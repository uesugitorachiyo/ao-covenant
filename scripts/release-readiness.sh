#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READINESS_DIR="${COVENANT_RELEASE_READINESS_DIR:-"$ROOT/.covenant/release-readiness"}"
if [[ "$READINESS_DIR" != /* ]]; then
  READINESS_DIR="$ROOT/$READINESS_DIR"
fi
VERSION="${COVENANT_RELEASE_VERSION:-v0.1.0-readiness}"
if [[ -n "${COVENANT_RELEASE_COMMIT:-}" ]]; then
  COMMIT="$COVENANT_RELEASE_COMMIT"
elif git -C "$ROOT" rev-parse --short HEAD >/dev/null 2>&1; then
  COMMIT="$(git -C "$ROOT" rev-parse --short HEAD)"
else
  COMMIT="unknown"
fi
DATE_VALUE="${COVENANT_RELEASE_DATE:-"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}"
HOST_GOOS="$(go env GOOS)"
HOST_GOARCH="$(go env GOARCH)"
TARGET="${COVENANT_RELEASE_TARGET:-"$HOST_GOOS/$HOST_GOARCH"}"

WORKSPACE="$READINESS_DIR"
ARTIFACTS="$READINESS_DIR/artifacts"
DIST="$READINESS_DIR/release"
BIN_DIR="$READINESS_DIR/bin"
BIN="$BIN_DIR/covenant"
SUMMARY="$READINESS_DIR/release-readiness-summary.json"
if [[ "$(go env GOOS)" == "windows" ]]; then
  BIN="$BIN.exe"
fi

rm -rf "$READINESS_DIR"
mkdir -p "$WORKSPACE/examples/risky-change" "$ARTIFACTS" "$DIST" "$BIN_DIR"

brief="examples/risky-change/brief.md"
contract_path="contract.json"
run_dir=".covenant/runs"
run_id="release-ready"
ledger_path="$run_dir/$run_id/events.ndjson"
evidence_path="$run_dir/$run_id/evidence-pack.json"
private_key="covenant-private-key.json"
public_key="covenant-public-key.json"
release_public_key="covenant-release-public-key.json"
bundle_path="release-ready-bundle.zip"
files_list="$WORKSPACE/schema-files.txt"

printf 'Create demo-output/report.txt\n' > "$WORKSPACE/$brief"
(cd "$ROOT" && go build -o "$BIN" ./cmd/covenant)

covenant() {
  (cd "$WORKSPACE" && "$BIN" "$@")
}

save_json() {
  local name="$1"
  shift
  covenant "$@" > "$ARTIFACTS/$name.json"
}

json_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '"%s"' "$value"
}

echo "release readiness: workspace=$READINESS_DIR"
echo "release readiness: target=$TARGET version=$VERSION commit=$COMMIT date=$DATE_VALUE"

save_json version version --json
save_json compile compile --brief "$brief" --out "$contract_path" --json
save_json lint-brief lint --brief "$brief" --json
save_json lint-contract lint --contract "$contract_path" --json
save_json run run \
  --contract "$contract_path" \
  --workspace "$WORKSPACE" \
  --out "$run_dir" \
  --run-id "$run_id" \
  --json
save_json verify verify \
  --ledger "$ledger_path" \
  --evidence "$evidence_path" \
  --json
save_json policy-explain policy explain --evidence "$evidence_path" --json
save_json policy-index policy index --evidence "$evidence_path" --json
save_json policy-spine policy spine --json

save_json bundle-keygen bundle keygen \
  --private "$private_key" \
  --public "$public_key" \
  --json
save_json bundle-export bundle export \
  --contract "$contract_path" \
  --ledger "$ledger_path" \
  --evidence "$evidence_path" \
  --workspace "$WORKSPACE" \
  --out "$bundle_path" \
  --sign-key "$private_key" \
  --json
save_json bundle-verify verify \
  --bundle "$bundle_path" \
  --public-key "$public_key" \
  --json
save_json bundle-inspect bundle inspect \
  --bundle "$bundle_path" \
  --public-key "$public_key" \
  --json
save_json bundle-report bundle report \
  --bundle "$bundle_path" \
  --public-key "$public_key" \
  --json

save_json release-package release package \
  --source "$ROOT" \
  --out "$DIST" \
  --version "$VERSION" \
  --commit "$COMMIT" \
  --date "$DATE_VALUE" \
  --target "$TARGET" \
  --sign-key "$private_key" \
  --json
cp "$WORKSPACE/$public_key" "$DIST/$release_public_key"
covenant release verify \
  --dir "$DIST" \
  --public-key "$DIST/$release_public_key" > "$ARTIFACTS/release-verify.txt"
save_json release-verify release verify \
  --dir "$DIST" \
  --public-key "$DIST/$release_public_key" \
  --json
save_json release-inspect release inspect \
  --dir "$DIST" \
  --public-key "$DIST/$release_public_key" \
  --json

"$BIN" version --json > "$ARTIFACTS/binary-version.json"
"$BIN" release verify \
  --dir "$DIST" \
  --public-key "$DIST/$release_public_key" \
  --json > "$ARTIFACTS/binary-release-verify.json"

{
  printf '%s\n' "$contract_path"
  printf '%s\n' "$evidence_path"
  printf '%s\n' "$private_key"
  printf '%s\n' "$public_key"
  printf '%s\n' "release/manifest.json"
  printf '%s\n' "release/release-signature.json"
  printf '%s\n' "release/$release_public_key"
  (cd "$WORKSPACE" && find artifacts -name '*.json' ! -name 'schema-validation.json' -print | sort)
} > "$files_list"

covenant schema validate \
  --files-from "$files_list" \
  --json \
  --out "$ARTIFACTS/schema-validation.json" > "$ARTIFACTS/schema-validation.stdout"

json_report_count="$(find "$ARTIFACTS" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d '[:space:]')"
summary_validation_report_count=$((json_report_count + 1))
release_file_count="$(find "$DIST" -maxdepth 1 -type f | wc -l | tr -d '[:space:]')"

{
  printf '{\n'
  printf '  "schema_version": "covenant.release-readiness-summary.v1",\n'
  printf '  "status": "passed",\n'
  printf '  "version": %s,\n' "$(json_string "$VERSION")"
  printf '  "commit": %s,\n' "$(json_string "$COMMIT")"
  printf '  "date": %s,\n' "$(json_string "$DATE_VALUE")"
  printf '  "target": %s,\n' "$(json_string "$TARGET")"
  printf '  "platform": {\n'
  printf '    "os": %s,\n' "$(json_string "$HOST_GOOS")"
  printf '    "arch": %s,\n' "$(json_string "$HOST_GOARCH")"
  printf '    "script": "scripts/release-readiness.sh"\n'
  printf '  },\n'
  printf '  "checks": [\n'
  printf '    "version",\n'
  printf '    "compile",\n'
  printf '    "lint-brief",\n'
  printf '    "lint-contract",\n'
  printf '    "run",\n'
  printf '    "verify",\n'
  printf '    "policy-explain",\n'
  printf '    "policy-index",\n'
  printf '    "policy-spine",\n'
  printf '    "bundle-keygen",\n'
  printf '    "bundle-export",\n'
  printf '    "bundle-verify",\n'
  printf '    "bundle-inspect",\n'
  printf '    "bundle-report",\n'
  printf '    "release-package",\n'
  printf '    "release-verify",\n'
  printf '    "release-inspect",\n'
  printf '    "binary-version",\n'
  printf '    "binary-release-verify",\n'
  printf '    "schema-validation",\n'
  printf '    "release-readiness-summary-validation"\n'
  printf '  ],\n'
  printf '  "artifact_counts": {\n'
  printf '    "json_reports": %s,\n' "$summary_validation_report_count"
  printf '    "generated_release_files": %s\n' "$release_file_count"
  printf '  },\n'
  printf '  "sensitivity": "summary-only; does not include workspace paths, signing key paths, bundle paths, checksums, manifest entries, or generated release asset names"\n'
  printf '}\n'
} > "$SUMMARY"

covenant schema validate \
  --schema covenant.release-readiness-summary.v1 \
  --file "$SUMMARY" \
  --json \
  --out "$ARTIFACTS/release-readiness-summary-validation.json" > "$ARTIFACTS/release-readiness-summary-validation.stdout"

echo "release readiness complete: $READINESS_DIR"
