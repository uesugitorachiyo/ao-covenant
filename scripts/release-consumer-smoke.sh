#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: release-consumer-smoke.sh <release-dir> [--repo owner/repo] [--out dir] [--skip-attestation]

Runs the public consumer verification smoke test for a downloaded AO Covenant
release directory. Set COVENANT_BIN to use a specific covenant binary; otherwise
the script uses covenant from PATH.

Required release files:
  manifest.json
  SHA256SUMS
  release-signature.json
  covenant-release-public-key.json

Options:
  --repo owner/repo       GitHub repository used for gh attestation verification.
                          Default: uesugitorachiyo/ao-covenant
  --out dir              Directory for release-verify.json, release-report.json,
                          release-inspect.json, and release-consumer-smoke.json.
                          Default: a temporary dir.
  --skip-attestation     Skip gh attestation verification.
  -h, --help             Show this help text.

Do not paste private keys, credentials, production evidence bundles, unreleased bundles, or local machine paths into public issues when reporting failures.
USAGE
}

fail() {
  printf 'release consumer smoke: %s\n' "$*" >&2
  exit 1
}

require_command() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    fail "missing required command: $name"
  fi
}

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    fail "missing required release file: $path"
  fi
}

REPO="uesugitorachiyo/ao-covenant"
OUT_DIR=""
SKIP_ATTESTATION=false
COVENANT_BIN="${COVENANT_BIN:-covenant}"
RELEASE_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires owner/repo"
      REPO="$2"
      shift 2
      ;;
    --out)
      [[ $# -ge 2 ]] || fail "--out requires a directory"
      OUT_DIR="$2"
      shift 2
      ;;
    --skip-attestation)
      SKIP_ATTESTATION=true
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --*)
      fail "unknown option: $1"
      ;;
    *)
      if [[ -n "$RELEASE_DIR" ]]; then
        fail "only one release directory may be provided"
      fi
      RELEASE_DIR="$1"
      shift
      ;;
  esac
done

if [[ -z "$RELEASE_DIR" ]]; then
  usage >&2
  fail "release directory is required"
fi
if [[ ! -d "$RELEASE_DIR" ]]; then
  fail "release directory does not exist: $RELEASE_DIR"
fi

RELEASE_DIR="$(cd "$RELEASE_DIR" && pwd -P)"
PUBLIC_KEY="$RELEASE_DIR/covenant-release-public-key.json"

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ao-covenant-release-smoke.XXXXXX")"
else
  mkdir -p "$OUT_DIR"
  OUT_DIR="$(cd "$OUT_DIR" && pwd -P)"
fi

require_command "$COVENANT_BIN"
if [[ "$SKIP_ATTESTATION" != "true" ]]; then
  require_command gh
fi

SUMMARY_JSON="$OUT_DIR/release-consumer-smoke.json"

require_file "$RELEASE_DIR/manifest.json"
require_file "$RELEASE_DIR/SHA256SUMS"
require_file "$RELEASE_DIR/release-signature.json"
require_file "$PUBLIC_KEY"

echo "release consumer smoke: release=$RELEASE_DIR"
echo "release consumer smoke: outputs=$OUT_DIR"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$RELEASE_DIR" && sha256sum -c SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd "$RELEASE_DIR" && shasum -a 256 -c SHA256SUMS)
else
  fail "missing checksum tool: install sha256sum or shasum"
fi

# Equivalent public command:
# covenant release verify --dir "$RELEASE_DIR" --public-key "$PUBLIC_KEY" --json
"$COVENANT_BIN" release verify \
  --dir "$RELEASE_DIR" \
  --public-key "$PUBLIC_KEY" \
  --json > "$OUT_DIR/release-verify.json"

# Equivalent public command:
# covenant release report --dir "$RELEASE_DIR" --public-key "$PUBLIC_KEY" --format json --out "$OUT_DIR/release-report.json"
"$COVENANT_BIN" release report \
  --dir "$RELEASE_DIR" \
  --public-key "$PUBLIC_KEY" \
  --format json \
  --out "$OUT_DIR/release-report.json"

# Equivalent public command:
# covenant release inspect --dir "$RELEASE_DIR" --public-key "$PUBLIC_KEY" --json
"$COVENANT_BIN" release inspect \
  --dir "$RELEASE_DIR" \
  --public-key "$PUBLIC_KEY" \
  --json > "$OUT_DIR/release-inspect.json"

# Equivalent public commands:
# covenant schema validate --file "$OUT_DIR/release-verify.json"
# covenant schema validate --file "$OUT_DIR/release-report.json"
# covenant schema validate --file "$OUT_DIR/release-inspect.json"
"$COVENANT_BIN" schema validate --file "$OUT_DIR/release-verify.json"
"$COVENANT_BIN" schema validate --file "$OUT_DIR/release-report.json"
"$COVENANT_BIN" schema validate --file "$OUT_DIR/release-inspect.json"

REPLACEMENT_POLICY="$RELEASE_DIR/release-replacement-policy.json"
REPLACEMENT_POLICY_PRESENT=false
if [[ -f "$REPLACEMENT_POLICY" ]]; then
  REPLACEMENT_POLICY_PRESENT=true
  "$COVENANT_BIN" schema validate \
    --schema covenant.release-replacement-policy.v1 \
    --file "$REPLACEMENT_POLICY"
fi

ATTESTATION_CHECKED=false
ATTESTATION_STATUS=skipped
if [[ "$SKIP_ATTESTATION" != "true" ]]; then
  ATTESTATION_CHECKED=true
  ATTESTATION_STATUS=passed
  # Equivalent public command:
  # gh attestation verify "$RELEASE_DIR/manifest.json" --repo "$REPO"
  gh attestation verify "$RELEASE_DIR/manifest.json" --repo "$REPO"
  if [[ -f "$REPLACEMENT_POLICY" ]]; then
    # Equivalent public command:
    # gh attestation verify "$RELEASE_DIR/release-replacement-policy.json" --repo "$REPO"
    gh attestation verify "$REPLACEMENT_POLICY" --repo "$REPO"
  fi
fi

# Equivalent public command:
# covenant schema validate --schema covenant.release-consumer-smoke-result.v1 --file "$OUT_DIR/release-consumer-smoke.json"
cat > "$SUMMARY_JSON" <<JSON
{
  "schema_version": "covenant.release-consumer-smoke-result.v1",
  "status": "passed",
  "attestation_skipped": $SKIP_ATTESTATION,
  "attestation_checked": $ATTESTATION_CHECKED,
  "replacement_policy_present": $REPLACEMENT_POLICY_PRESENT,
  "release_files": [
    "manifest.json",
    "SHA256SUMS",
    "release-signature.json",
    "covenant-release-public-key.json"
  ],
  "report_files": [
    "release-verify.json",
    "release-report.json",
    "release-inspect.json"
  ],
  "checks": [
    {"name": "required-files", "status": "passed"},
    {"name": "checksums", "status": "passed"},
    {"name": "release-verify", "status": "passed"},
    {"name": "release-report", "status": "passed"},
    {"name": "release-inspect", "status": "passed"},
    {"name": "schema-validation", "status": "passed"},
    {"name": "attestation", "status": "$ATTESTATION_STATUS"}
  ]
}
JSON
"$COVENANT_BIN" schema validate \
  --schema covenant.release-consumer-smoke-result.v1 \
  --file "$SUMMARY_JSON"

echo "release_consumer_smoke=passed"
echo "release_consumer_smoke_result=$SUMMARY_JSON"
echo "release consumer smoke complete: outputs=$OUT_DIR"
