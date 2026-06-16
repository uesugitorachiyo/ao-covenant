#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-dist}"
VERSION="${VERSION:-}"
REPLACE_EXISTING_ASSETS="${REPLACE_EXISTING_ASSETS:-false}"
REPLACEMENT_REASON="${REPLACEMENT_REASON:-}"

if [[ -z "$VERSION" ]]; then
  echo "VERSION is required" >&2
  exit 1
fi

if [[ ! -d "$DIST_DIR" ]]; then
  echo "release dist directory does not exist: $DIST_DIR" >&2
  exit 1
fi

tmp_parent="${RUNNER_TEMP:-}"
if [[ -n "$tmp_parent" && -d "$tmp_parent" ]]; then
  tmp_dir="$(mktemp -d "$tmp_parent/release-replacement-preflight.XXXXXX")"
else
  tmp_dir="$(mktemp -d)"
fi
trap 'rm -rf "$tmp_dir"' EXIT

existing_assets="$tmp_dir/existing-release-assets.txt"
new_assets="$tmp_dir/new-release-assets.txt"
conflicts_file="$tmp_dir/conflicting-release-assets.txt"

json_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '"%s"' "$value"
}

json_array_from_lines() {
  local file="$1"
  local first="true"
  printf '['
  while IFS= read -r item; do
    [[ -n "$item" ]] || continue
    if [[ "$first" == "true" ]]; then
      first="false"
    else
      printf ','
    fi
    json_string "$item"
  done < "$file"
  printf ']'
}

require_policy_metadata() {
  if [[ -z "$REPLACEMENT_REASON" ]]; then
    echo "REPLACEMENT_REASON is required when replace_existing_assets=true" >&2
    exit 1
  fi
  if [[ -z "${GITHUB_REPOSITORY:-}" ]]; then
    echo "GITHUB_REPOSITORY is required when replace_existing_assets=true" >&2
    exit 1
  fi
  if [[ -z "${GITHUB_RUN_ID:-}" ]]; then
    echo "GITHUB_RUN_ID is required when replace_existing_assets=true" >&2
    exit 1
  fi
  if [[ -z "${GITHUB_RUN_ATTEMPT:-}" ]]; then
    echo "GITHUB_RUN_ATTEMPT is required when replace_existing_assets=true" >&2
    exit 1
  fi
}

write_replacement_policy() {
  local policy_path="$DIST_DIR/release-replacement-policy.json"
  local created_at
  created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  {
    printf '{\n'
    printf '  "schema_version": "covenant.release-replacement-policy.v1",\n'
    printf '  "version": %s,\n' "$(json_string "$VERSION")"
    printf '  "reason": %s,\n' "$(json_string "$REPLACEMENT_REASON")"
    printf '  "created_at": %s,\n' "$(json_string "$created_at")"
    printf '  "github": {\n'
    printf '    "repository": %s,\n' "$(json_string "$GITHUB_REPOSITORY")"
    printf '    "run_id": %s,\n' "$(json_string "$GITHUB_RUN_ID")"
    printf '    "run_attempt": %s\n' "$(json_string "$GITHUB_RUN_ATTEMPT")"
    printf '  },\n'
    printf '  "replaced_assets": '
    json_array_from_lines "$conflicts_file"
    printf '\n'
    printf '}\n'
  } > "$policy_path"

  (cd "$ROOT" && go run ./cmd/covenant schema validate --schema covenant.release-replacement-policy.v1 --file "$policy_path")
}

find "$DIST_DIR" -maxdepth 1 -type f -exec basename {} \; | sort > "$new_assets"

release_exists="false"
if [[ -n "${COVENANT_RELEASE_EXISTING_ASSETS_FILE:-}" ]]; then
  if [[ ! -f "$COVENANT_RELEASE_EXISTING_ASSETS_FILE" ]]; then
    echo "COVENANT_RELEASE_EXISTING_ASSETS_FILE does not exist: $COVENANT_RELEASE_EXISTING_ASSETS_FILE" >&2
    exit 1
  fi
  sort "$COVENANT_RELEASE_EXISTING_ASSETS_FILE" > "$existing_assets"
  release_exists="true"
elif gh release view "$VERSION" >/dev/null 2>&1; then
  gh release view "$VERSION" --json assets --jq '.assets[].name' | sort > "$existing_assets"
  release_exists="true"
fi

if [[ "$release_exists" != "true" ]]; then
  echo "release replacement preflight: no existing release for $VERSION"
  exit 0
fi

if [[ "$REPLACE_EXISTING_ASSETS" == "true" ]]; then
  printf '%s\n' "release-replacement-policy.json" >> "$new_assets"
  sort -u "$new_assets" -o "$new_assets"
fi

comm -12 "$existing_assets" "$new_assets" > "$conflicts_file" || true

if [[ -s "$conflicts_file" && "$REPLACE_EXISTING_ASSETS" != "true" ]]; then
  echo "release asset replacement requires workflow_dispatch input replace_existing_assets=true" >&2
  echo "conflicting assets:" >&2
  cat "$conflicts_file" >&2
  exit 1
fi

if [[ "$REPLACE_EXISTING_ASSETS" == "true" ]]; then
  require_policy_metadata
  write_replacement_policy
  echo "release replacement preflight: wrote $DIST_DIR/release-replacement-policy.json"
else
  echo "release replacement preflight: no asset conflicts for $VERSION"
fi
