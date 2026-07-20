#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tarfile
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER_PATH = ROOT / "scripts" / "verify-release-modernization.py"
SPEC = importlib.util.spec_from_file_location("release_modernization_verifier", VERIFIER_PATH)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def run(command, *, env=None, accepted=(0,)):
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    if completed.returncode not in accepted:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(map(str, command))}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sanitized_environment():
    forbidden = (
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "API_KEY",
        "OPENAI",
        "ANTHROPIC",
        "AZURE",
        "AWS_",
        "GOOGLE_",
    )
    return {
        key: value
        for key, value in os.environ.items()
        if not any(marker in key.upper() for marker in forbidden)
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--approved-manifest", required=True)
    parser.add_argument("--binding", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    manifest, _ = VERIFIER.validate_manifest(args.approved_manifest)
    binding, _ = VERIFIER.read_json(args.binding, "release input binding", 16384)
    expected_binding = {
        "source_sha": manifest["source_sha"],
        "version": manifest["version"],
        "tag": manifest["tag"],
        "build_date": manifest["build_date"],
        "approved_manifest_sha256": VERIFIER.digest_path(args.approved_manifest),
        "status": "passed",
    }
    for key, expected in expected_binding.items():
        if binding.get(key) != expected:
            raise RuntimeError(f"release input binding {key} mismatch")
    targets = [target for target in manifest["targets"] if target["target"] == args.target]
    if len(targets) != 1:
        raise RuntimeError("requested target is not in the approved manifest")
    target = targets[0]
    go_env = run(["go", "env", "GOOS", "GOARCH"]).stdout.splitlines()
    if go_env != [target["goos"], target["goarch"]]:
        raise RuntimeError(
            f"native runner mismatch: got {go_env}, "
            f"want {[target['goos'], target['goarch']]}"
        )

    out = pathlib.Path(args.out).resolve()
    if out.exists() and any(out.iterdir()):
        raise RuntimeError("candidate output directory must be empty")
    out.mkdir(parents=True, exist_ok=True)
    binary = out / target["binary"]
    prefix = "github.com/uesugitorachiyo/ao-covenant/internal/buildinfo"
    ldflags = " ".join(
        (
            "-s",
            "-w",
            "-X",
            f"{prefix}.Version={manifest['version']}",
            "-X",
            f"{prefix}.Commit={manifest['source_sha']}",
            "-X",
            f"{prefix}.Date={manifest['build_date']}",
        )
    )
    run(
        [
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            ldflags,
            "-o",
            str(binary),
            "./cmd/covenant",
        ]
    )

    candidate_env = sanitized_environment()
    help_result = run([str(binary), "--help"], env=candidate_env, accepted=(0, 2))
    help_text = help_result.stdout + help_result.stderr
    if "usage:" not in help_text.lower():
        raise RuntimeError("candidate help readback did not contain usage")
    (out / "help-readback.txt").write_text(help_text)

    version_result = run([str(binary), "version", "--json"], env=candidate_env)
    version_readback = json.loads(version_result.stdout)
    expected_version = {
        "schema_version": "covenant.version-result.v1",
        "version": manifest["version"],
        "commit": manifest["source_sha"],
        "date": manifest["build_date"],
        "os": target["goos"],
        "arch": target["goarch"],
    }
    for key, expected in expected_version.items():
        if version_readback.get(key) != expected:
            raise RuntimeError(f"candidate version readback {key} mismatch")
    canonical_write(out / "version-readback.json", version_readback)

    provider_smoke = run(
        [str(binary), "schema", "catalog", "--json"],
        env=candidate_env,
    )
    smoke_payload = json.loads(provider_smoke.stdout)
    if not isinstance(smoke_payload, dict) or not smoke_payload.get("schema_version"):
        raise RuntimeError("provider-free schema-catalog smoke returned malformed JSON")
    canonical_write(
        out / "provider-free-smoke.json",
        {
            "schema_version": "ao.covenant.provider-free-smoke.v1",
            "status": "passed",
            "provider_credentials_used": False,
            "network_provider_calls_attempted": False,
        },
    )
    for name in ("LICENSE", "NOTICE"):
        (out / name).write_bytes((ROOT / name).read_bytes())

    archive = out / target["archive"]
    archive_names = (target["binary"], "LICENSE", "NOTICE")
    if target["goos"] == "windows":
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
            for name in archive_names:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                permissions = 0o755 if name == target["binary"] else 0o644
                info.external_attr = (stat.S_IFREG | permissions) << 16
                handle.writestr(info, (out / name).read_bytes())
    else:
        with tarfile.open(archive, "w:gz") as handle:
            for name in archive_names:
                handle.add(out / name, arcname=name, recursive=False)

    canonical_write(
        out / "provenance.json",
        {
            "schema_version": "ao.covenant.native-candidate-provenance.v1",
            "source_sha": manifest["source_sha"],
            "version": manifest["version"],
            "tag": manifest["tag"],
            "build_date": manifest["build_date"],
            "target": target["target"],
            "runner": target["runner"],
            "approved_manifest_sha256": binding["approved_manifest_sha256"],
        },
    )
    summary = {
        "schema_version": "ao.covenant.native-release-candidate.v1",
        "status": "passed",
        "source_sha": manifest["source_sha"],
        "version": manifest["version"],
        "tag": manifest["tag"],
        "build_date": manifest["build_date"],
        "target": target["target"],
        "runner": target["runner"],
        "goos": target["goos"],
        "goarch": target["goarch"],
        "binary": target["binary"],
        "binary_sha256": digest(binary),
        "archive": target["archive"],
        "archive_sha256": digest(archive),
        "approved_manifest_sha256": binding["approved_manifest_sha256"],
        "help_status": "passed",
        "version_source_status": "passed",
        "provider_free_status": "passed",
        "provider_credentials_used": False,
        "network_provider_calls_attempted": False,
    }
    canonical_write(out / "candidate-summary.json", summary)
    checksums = []
    for path in sorted(out.iterdir(), key=lambda item: item.name):
        if path.name != "SHA256SUMS":
            checksums.append(f"{digest(path).removeprefix('sha256:')}  {path.name}\n")
    (out / "SHA256SUMS").write_text("".join(checksums))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, json.JSONDecodeError, VERIFIER.VerificationError) as error:
        print(f"candidate build failed: {error}", file=sys.stderr)
        raise SystemExit(1)
