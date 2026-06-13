#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
READINESS_DIR="${COVENANT_RELEASE_READINESS_DIR:-"$ROOT/.covenant/release-readiness"}"
VERSION="${COVENANT_RELEASE_VERSION:-v0.1.0-readiness}"
if [[ -n "${COVENANT_RELEASE_COMMIT:-}" ]]; then
  COMMIT="$COVENANT_RELEASE_COMMIT"
elif git -C "$ROOT" rev-parse --short HEAD >/dev/null 2>&1; then
  COMMIT="$(git -C "$ROOT" rev-parse --short HEAD)"
else
  COMMIT="unknown"
fi
DATE_VALUE="${COVENANT_RELEASE_DATE:-"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}"
TARGET="${COVENANT_RELEASE_TARGET:-"$(go env GOOS)/$(go env GOARCH)"}"

WORKSPACE="$READINESS_DIR"
ARTIFACTS="$READINESS_DIR/artifacts"
DIST="$READINESS_DIR/release"
BIN_DIR="$READINESS_DIR/bin"
BIN="$BIN_DIR/covenant"
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
covenant release verify \
  --dir "$DIST" \
  --public-key "$public_key" > "$ARTIFACTS/release-verify.txt"
save_json release-verify release verify \
  --dir "$DIST" \
  --public-key "$public_key" \
  --json
save_json release-inspect release inspect \
  --dir "$DIST" \
  --public-key "$public_key" \
  --json

"$BIN" version --json > "$ARTIFACTS/binary-version.json"
"$BIN" release verify \
  --dir "$DIST" \
  --public-key "$WORKSPACE/$public_key" \
  --json > "$ARTIFACTS/binary-release-verify.json"

{
  printf '%s\n' "$contract_path"
  printf '%s\n' "$evidence_path"
  printf '%s\n' "$private_key"
  printf '%s\n' "$public_key"
  printf '%s\n' "release/manifest.json"
  printf '%s\n' "release/release-signature.json"
  (cd "$WORKSPACE" && find artifacts -name '*.json' ! -name 'schema-validation.json' -print | sort)
} > "$files_list"

covenant schema validate \
  --files-from "$files_list" \
  --json \
  --out "$ARTIFACTS/schema-validation.json" > "$ARTIFACTS/schema-validation.stdout"

echo "release readiness complete: $READINESS_DIR"
