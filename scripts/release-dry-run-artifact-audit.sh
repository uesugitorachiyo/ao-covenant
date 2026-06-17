#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-dist}"
VERSION="${VERSION:-}"
DRY_RUN="${DRY_RUN:-false}"
AUDIT_JSON="${COVENANT_RELEASE_DRY_RUN_ARTIFACT_AUDIT_JSON:-"$DIST_DIR/release-dry-run-artifact-audit.json"}"

if [[ -z "$VERSION" ]]; then
  echo "VERSION is required" >&2
  exit 2
fi
if [[ "$DRY_RUN" != "true" ]]; then
  echo "release dry-run artifact audit requires DRY_RUN=true" >&2
  exit 2
fi

python3 - "$DIST_DIR" "$VERSION" "$AUDIT_JSON" "${GITHUB_REPOSITORY:-}" "${GITHUB_RUN_ID:-}" "${GITHUB_RUN_ATTEMPT:-}" <<'PY'
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

dist = Path(sys.argv[1])
version = sys.argv[2]
audit_json = Path(sys.argv[3])
repository = sys.argv[4]
run_id = sys.argv[5]
run_attempt = sys.argv[6]

required = [
    ("manifest.json", "manifest"),
    ("SHA256SUMS", "checksums"),
    ("release-signature.json", "signature"),
    ("covenant-release-public-key.json", "public-key"),
    ("release-package.json", "report"),
    ("release-verify.json", "report"),
    ("release-report.json", "report"),
]
private_key_markers = [
    "private_key",
    "covenant.bundle-private-key.v1",
    "BEGIN PRIVATE KEY",
]

findings = []
required_files = []
for name, kind in required:
    present = (dist / name).is_file()
    required_files.append({"name": name, "present": present, "kind": kind})
    if not present:
        findings.append(f"missing required artifact: {name}")

artifacts = []
for path in sorted(dist.iterdir() if dist.is_dir() else []):
    if not path.is_file():
        continue
    if path.resolve() == audit_json.resolve():
        continue
    name = path.name
    if name == "manifest.json":
        kind = "manifest"
    elif name == "SHA256SUMS":
        kind = "checksums"
    elif name == "release-signature.json":
        kind = "signature"
    elif name == "covenant-release-public-key.json":
        kind = "public-key"
    elif name.endswith(".json"):
        kind = "report"
    elif name.startswith("ao-covenant_"):
        kind = "platform-binary"
    else:
        kind = "other"
    if name == "release-replacement-policy.json":
        kind = "replacement-policy"
    data = path.read_bytes()
    artifacts.append(
        {
            "name": name,
            "kind": kind,
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    )

for artifact in artifacts:
    name = artifact["name"]
    lower_name = name.lower()
    if "private" in lower_name or lower_name.endswith(".key") or "private-key" in lower_name:
        findings.append(f"forbidden private-key-looking artifact: {name}")
    path = dist / name
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for marker in private_key_markers:
        if marker in text:
            findings.append(f"forbidden private key marker in artifact: {name}")
            break

artifact_counts = {
    "total_files": len(artifacts),
    "json_reports": sum(1 for artifact in artifacts if artifact["name"].endswith(".json")),
    "platform_assets": sum(1 for artifact in artifacts if artifact["kind"] == "platform-binary"),
    "required_files_present": sum(1 for item in required_files if item["present"]),
    "forbidden_files": sum(1 for finding in findings if finding.startswith("forbidden ")),
}
contains_private_key_material = artifact_counts["forbidden_files"] > 0
status = "passed" if not findings else "failed"
payload = {
    "schema_version": "covenant.release-dry-run-artifact-audit.v1",
    "status": status,
    "version": version,
    "dry_run": True,
    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "required_files": required_files,
    "artifacts": artifacts,
    "artifact_counts": artifact_counts,
    "findings": findings,
    "trust_boundary": {
        "publishes_github_release": False,
        "mutates_github_releases": False,
        "generates_github_attestations": False,
        "stores_credentials": False,
        "contains_private_key_material": contains_private_key_material,
    },
}
if repository or run_id or run_attempt:
    payload["github"] = {}
    if repository:
        payload["github"]["repository"] = repository
    if run_id:
        payload["github"]["run_id"] = run_id
    if run_attempt:
        payload["github"]["run_attempt"] = run_attempt

audit_json.parent.mkdir(parents=True, exist_ok=True)
audit_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if status == "passed":
    print("release_dry_run_artifact_audit=passed")
else:
    print("release_dry_run_artifact_audit=failed")
print(f"release_dry_run_artifact_audit_json={audit_json}")
if status != "passed":
    raise SystemExit(1)
PY

go run ./cmd/covenant schema validate \
  --schema covenant.release-dry-run-artifact-audit.v1 \
  --file "$AUDIT_JSON" >/dev/null
