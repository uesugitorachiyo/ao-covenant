#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-dist}"
VERSION="${VERSION:-}"
REPLACE_EXISTING_ASSETS="${REPLACE_EXISTING_ASSETS:-false}"
REPLACEMENT_REASON="${REPLACEMENT_REASON:-}"
REPORT_JSON="${COVENANT_RELEASE_REPLACEMENT_REPORT_JSON:-}"
CREATED_AT="${COVENANT_RELEASE_REPLACEMENT_CREATED_AT:-"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}"

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
: > "$existing_assets"
: > "$conflicts_file"

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

json_bool() {
  case "$1" in
    true) printf 'true' ;;
    *) printf 'false' ;;
  esac
}

json_optional_github() {
  local has_previous="$1"
  if [[ -z "${GITHUB_REPOSITORY:-}" && -z "${GITHUB_RUN_ID:-}" && -z "${GITHUB_RUN_ATTEMPT:-}" ]]; then
    return
  fi
  if [[ "$has_previous" == "true" ]]; then
    printf ',\n'
  fi
  printf '  "github": {\n'
  local first="true"
  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    printf '    "repository": %s' "$(json_string "$GITHUB_REPOSITORY")"
    first="false"
  fi
  if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
    if [[ "$first" == "false" ]]; then
      printf ',\n'
    fi
    printf '    "run_id": %s' "$(json_string "$GITHUB_RUN_ID")"
    first="false"
  fi
  if [[ -n "${GITHUB_RUN_ATTEMPT:-}" ]]; then
    if [[ "$first" == "false" ]]; then
      printf ',\n'
    fi
    printf '    "run_attempt": %s' "$(json_string "$GITHUB_RUN_ATTEMPT")"
  fi
  printf '\n'
  printf '  }'
}

write_preflight_report() {
  local status="$1"
  local error_message="${2:-}"
  local policy_path="${3:-}"
  if [[ -z "$REPORT_JSON" ]]; then
    return
  fi

  mkdir -p "$(dirname "$REPORT_JSON")"
  {
    printf '{\n'
    printf '  "schema_version": "covenant.release-replacement-preflight-report.v1",\n'
    printf '  "version": %s,\n' "$(json_string "$VERSION")"
    printf '  "status": %s,\n' "$(json_string "$status")"
    printf '  "replace_existing_assets": %s,\n' "$(json_bool "$REPLACE_EXISTING_ASSETS")"
    printf '  "release_exists": %s,\n' "$(json_bool "$release_exists")"
    printf '  "created_at": %s' "$(json_string "$CREATED_AT")"
    json_optional_github true
    if [[ -n "$REPLACEMENT_REASON" ]]; then
      printf ',\n'
      printf '  "replacement_reason": %s' "$(json_string "$REPLACEMENT_REASON")"
    fi
    if [[ -n "$policy_path" ]]; then
      printf ',\n'
      printf '  "policy_path": %s' "$(json_string "$policy_path")"
    fi
    if [[ -n "$error_message" ]]; then
      printf ',\n'
      printf '  "error": %s' "$(json_string "$error_message")"
    fi
    printf ',\n'
    printf '  "assets": {\n'
    printf '    "new": '
    json_array_from_lines "$new_assets"
    printf ',\n'
    printf '    "existing": '
    json_array_from_lines "$existing_assets"
    printf ',\n'
    printf '    "conflicting": '
    json_array_from_lines "$conflicts_file"
    printf '\n'
    printf '  }\n'
    printf '}\n'
  } > "$REPORT_JSON"

  (cd "$ROOT" && go run ./cmd/covenant schema validate --schema covenant.release-replacement-preflight-report.v1 --file "$REPORT_JSON")
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

  {
    printf '{\n'
    printf '  "schema_version": "covenant.release-replacement-policy.v1",\n'
    printf '  "version": %s,\n' "$(json_string "$VERSION")"
    printf '  "reason": %s,\n' "$(json_string "$REPLACEMENT_REASON")"
    printf '  "created_at": %s,\n' "$(json_string "$CREATED_AT")"
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
  write_preflight_report "no_existing_release"
  echo "release replacement preflight: no existing release for $VERSION"
  exit 0
fi

if [[ "$REPLACE_EXISTING_ASSETS" == "true" ]]; then
  printf '%s\n' "release-replacement-policy.json" >> "$new_assets"
  sort -u "$new_assets" -o "$new_assets"
fi

comm -12 "$existing_assets" "$new_assets" > "$conflicts_file" || true

if [[ -s "$conflicts_file" && "$REPLACE_EXISTING_ASSETS" != "true" ]]; then
  write_preflight_report "blocked_existing_assets" "release asset replacement requires workflow_dispatch input replace_existing_assets=true"
  echo "release asset replacement requires workflow_dispatch input replace_existing_assets=true" >&2
  echo "conflicting assets:" >&2
  cat "$conflicts_file" >&2
  exit 1
fi

if [[ "$REPLACE_EXISTING_ASSETS" == "true" ]]; then
  require_policy_metadata
  write_replacement_policy
  write_preflight_report "replacement_policy_written" "" "release-replacement-policy.json"
  echo "release replacement preflight: wrote $DIST_DIR/release-replacement-policy.json"
else
  write_preflight_report "no_conflicts"
  echo "release replacement preflight: no asset conflicts for $VERSION"
fi
