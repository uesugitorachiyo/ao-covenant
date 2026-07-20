#!/usr/bin/env python3
import argparse
import hashlib
import json
import pathlib
import re
import stat
import struct
import sys
import tarfile
import zipfile


MAX_MANIFEST_BYTES = 32768
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-.][0-9A-Za-z.-]+)?$")
TARGETS = (
    ("linux-amd64", "ubuntu-latest", "linux", "amd64", ""),
    ("darwin-amd64", "macos-15-intel", "darwin", "amd64", ""),
    ("windows-amd64", "windows-latest", "windows", "amd64", ".exe"),
)
MANIFEST_KEYS = {
    "schema_version",
    "repository",
    "source_sha",
    "version",
    "tag",
    "build_date",
    "targets",
    "required_package_files",
    "safety_boundaries",
}
TARGET_KEYS = {"target", "runner", "goos", "goarch", "binary", "archive"}
SAFETY_KEYS = {
    "provider_credentials_allowed",
    "network_provider_calls_allowed",
    "public_mutation_allowed",
    "inbound_service_allowed",
    "arbitrary_remote_command_allowed",
}
SUMMARY_KEYS = {
    "schema_version",
    "status",
    "source_sha",
    "version",
    "tag",
    "build_date",
    "target",
    "runner",
    "goos",
    "goarch",
    "binary",
    "binary_sha256",
    "archive",
    "archive_sha256",
    "approved_manifest_sha256",
    "help_status",
    "version_source_status",
    "provider_free_status",
    "provider_credentials_used",
    "network_provider_calls_attempted",
}


class VerificationError(Exception):
    pass


def fail(message):
    raise VerificationError(message)


def read_bytes(path, label, limit=None):
    path = pathlib.Path(path)
    try:
        data = path.read_bytes()
    except OSError as error:
        fail(f"cannot read {label}: {error}")
    if limit is not None and len(data) > limit:
        fail(f"{label} exceeds {limit} bytes")
    return data


def read_json(path, label, limit=None):
    data = read_bytes(path, label, limit)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"malformed {label}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value, data


def exact_keys(value, expected, label):
    observed = set(value)
    if observed != expected:
        fail(
            f"{label} fields mismatch: missing={sorted(expected - observed)} "
            f"unknown={sorted(observed - expected)}"
        )


def digest_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_path(path):
    return digest_bytes(read_bytes(path, str(path)))


def write_json(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def expected_targets(version):
    values = []
    for label, runner, goos, goarch, suffix in TARGETS:
        extension = "zip" if goos == "windows" else "tar.gz"
        values.append(
            {
                "target": label,
                "runner": runner,
                "goos": goos,
                "goarch": goarch,
                "binary": f"ao-covenant_{version}_{goos}_{goarch}{suffix}",
                "archive": f"ao-covenant_{version}_{label}.{extension}",
            }
        )
    return values


def validate_manifest(path):
    value, data = read_json(path, "approved manifest", MAX_MANIFEST_BYTES)
    exact_keys(value, MANIFEST_KEYS, "approved manifest")
    if value["schema_version"] != "ao.covenant.release-approved-manifest.v1":
        fail("unsupported approved manifest schema")
    if value["repository"] != "uesugitorachiyo/ao-covenant":
        fail("approved manifest repository mismatch")
    if not isinstance(value["source_sha"], str) or not SHA_RE.fullmatch(
        value["source_sha"]
    ):
        fail("approved manifest source SHA is invalid")
    if not isinstance(value["version"], str) or not VERSION_RE.fullmatch(
        value["version"]
    ):
        fail("approved manifest version is invalid")
    if value["tag"] != value["version"]:
        fail("approved manifest tag must equal version")
    if not isinstance(value["build_date"], str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        value["build_date"],
    ):
        fail("approved manifest build_date is invalid")
    if value["required_package_files"] != ["LICENSE", "NOTICE"]:
        fail("approved manifest package files mismatch")
    safety = value["safety_boundaries"]
    if not isinstance(safety, dict):
        fail("approved manifest safety_boundaries must be an object")
    exact_keys(safety, SAFETY_KEYS, "approved manifest safety boundaries")
    if any(safety.values()) or any(type(flag) is not bool for flag in safety.values()):
        fail("approved manifest contains unsafe boundary flags")
    if value["targets"] != expected_targets(value["version"]):
        fail("approved manifest native target inventory mismatch")
    for index, target in enumerate(value["targets"]):
        if not isinstance(target, dict):
            fail(f"approved manifest target {index} must be an object")
        exact_keys(target, TARGET_KEYS, f"approved manifest target {index}")
    return value, data


def command_inputs(args):
    manifest, manifest_bytes = validate_manifest(args.manifest)
    if not DIGEST_RE.fullmatch(args.expected_digest):
        fail("expected approved manifest digest is invalid")
    if digest_bytes(manifest_bytes) != args.expected_digest:
        fail("approved manifest digest mismatch")
    if not SHA_RE.fullmatch(args.expected_source):
        fail("expected source SHA is invalid")
    if manifest["source_sha"] != args.expected_source:
        fail("approved manifest source SHA mismatch")
    if manifest["version"] != args.expected_version:
        fail("approved manifest version mismatch")
    if manifest["tag"] != args.expected_tag:
        fail("approved manifest tag mismatch")
    if args.expected_tag != args.expected_version:
        fail("tag must exactly equal version")
    repository_version = read_bytes(
        args.repository_version_file, "repository version", 128
    ).decode("ascii", "strict").strip()
    if repository_version != args.expected_version:
        fail("repository version mismatch")
    if args.dry_run not in ("true", "false"):
        fail("dry_run must be true or false")
    expected_confirmation = (
        f"publish:{args.expected_tag}:{args.expected_source}:{args.expected_digest}"
    )
    if args.dry_run == "true":
        if args.live_confirmation:
            fail("dry run must not include live confirmation")
    elif args.live_confirmation != expected_confirmation:
        fail("live confirmation mismatch")
    write_json(
        args.out,
        {
            "schema_version": "ao.covenant.release-input-binding.v1",
            "status": "passed",
            "source_sha": args.expected_source,
            "version": args.expected_version,
            "tag": args.expected_tag,
            "build_date": manifest["build_date"],
            "approved_manifest_sha256": args.expected_digest,
            "dry_run": args.dry_run == "true",
            "live_confirmation_verified": args.dry_run == "false",
            "publication_status": "not_attempted",
            "tag_creation_attempted": False,
            "release_creation_attempted": False,
            "public_upload_attempted": False,
        },
    )


def validate_binary_format(path, goos):
    data = read_bytes(path, "candidate binary")
    if goos == "linux":
        if len(data) < 20 or data[:6] != b"\x7fELF\x02\x01":
            fail("Linux candidate is not a 64-bit little-endian ELF binary")
        if struct.unpack("<H", data[18:20])[0] != 62:
            fail("Linux candidate architecture is not amd64")
    elif goos == "darwin":
        if len(data) < 8 or struct.unpack("<I", data[:4])[0] != 0xFEEDFACF:
            fail("macOS candidate is not a 64-bit Mach-O binary")
        if struct.unpack("<I", data[4:8])[0] != 0x01000007:
            fail("macOS candidate architecture is not x86_64")
    else:
        if len(data) < 0x88 or data[:2] != b"MZ":
            fail("Windows candidate is not a PE binary")
        offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if offset + 6 > len(data) or data[offset : offset + 4] != b"PE\0\0":
            fail("Windows candidate PE header is invalid")
        if struct.unpack("<H", data[offset + 4 : offset + 6])[0] != 0x8664:
            fail("Windows candidate architecture is not amd64")


def validate_archive(path, target, candidate_dir):
    expected = {target["binary"], "LICENSE", "NOTICE"}
    if target["goos"] == "windows":
        try:
            with zipfile.ZipFile(path) as handle:
                infos = handle.infolist()
                names = [info.filename for info in infos]
                if set(names) != expected or len(names) != len(expected):
                    fail("Windows archive inventory mismatch")
                for info in infos:
                    name = info.filename
                    entry = pathlib.PurePosixPath(name)
                    posix_mode = info.external_attr >> 16
                    if (
                        not name
                        or "\x00" in name
                        or "\\" in name
                        or name.startswith(("/", "//", "\\\\"))
                        or re.match(r"^[A-Za-z]:", name)
                        or entry.is_absolute()
                        or entry.name in ("", ".", "..")
                        or any(part in ("", ".", "..") for part in entry.parts)
                        or len(entry.parts) != 1
                        or info.create_system != 3
                        or not stat.S_ISREG(posix_mode)
                        or info.is_dir()
                        or (info.external_attr & 0x10) != 0
                    ):
                        fail("unsafe Windows archive entry")
                    if handle.read(info) != read_bytes(
                        candidate_dir / info.filename, "candidate archive member"
                    ):
                        fail("Windows archive member substitution")
        except (OSError, zipfile.BadZipFile) as error:
            fail(f"invalid Windows archive: {error}")
        return
    try:
        with tarfile.open(path, "r:gz") as handle:
            members = handle.getmembers()
            names = [member.name for member in members]
            if set(names) != expected or len(names) != len(expected):
                fail("tar archive inventory mismatch")
            for member in members:
                entry = pathlib.PurePosixPath(member.name)
                if (
                    entry.is_absolute()
                    or ".." in entry.parts
                    or len(entry.parts) != 1
                    or not member.isfile()
                    or member.issym()
                    or member.islnk()
                ):
                    fail("unsafe tar archive entry")
                extracted = handle.extractfile(member)
                if extracted is None or extracted.read() != read_bytes(
                    candidate_dir / member.name, "candidate archive member"
                ):
                    fail("tar archive member substitution")
    except (OSError, tarfile.TarError) as error:
        fail(f"invalid tar archive: {error}")


def validate_checksums(candidate_dir, expected_files):
    checksum_path = candidate_dir / "SHA256SUMS"
    lines = read_bytes(checksum_path, "candidate checksums", 16384).decode(
        "ascii", "strict"
    ).splitlines()
    expected = {
        name: digest_path(candidate_dir / name).removeprefix("sha256:")
        for name in expected_files
    }
    observed = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match.group(2) in observed:
            fail("malformed or duplicate candidate checksum entry")
        observed[match.group(2)] = match.group(1)
    if observed != expected:
        fail("candidate checksum inventory mismatch")


def validate_candidate(candidate_dir, target, manifest, binding):
    summary, _ = read_json(
        candidate_dir / "candidate-summary.json", "candidate summary", 16384
    )
    exact_keys(summary, SUMMARY_KEYS, "candidate summary")
    expected_values = {
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
        "archive": target["archive"],
        "approved_manifest_sha256": binding["approved_manifest_sha256"],
        "help_status": "passed",
        "version_source_status": "passed",
        "provider_free_status": "passed",
        "provider_credentials_used": False,
        "network_provider_calls_attempted": False,
    }
    for key, expected in expected_values.items():
        if summary.get(key) != expected:
            fail(f"candidate {target['target']} {key} mismatch")
    for key in ("binary_sha256", "archive_sha256"):
        if not isinstance(summary[key], str) or not DIGEST_RE.fullmatch(summary[key]):
            fail(f"candidate {target['target']} {key} is invalid")

    expected_files = {
        target["binary"],
        target["archive"],
        "LICENSE",
        "NOTICE",
        "help-readback.txt",
        "version-readback.json",
        "provider-free-smoke.json",
        "provenance.json",
        "candidate-summary.json",
    }
    observed_files = {
        path.name
        for path in candidate_dir.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if observed_files != expected_files | {"SHA256SUMS"}:
        fail(f"candidate {target['target']} file inventory mismatch")
    if any(path.is_symlink() or not path.is_file() for path in candidate_dir.iterdir()):
        fail(f"candidate {target['target']} contains unsafe file types")
    validate_checksums(candidate_dir, expected_files)
    binary_path = candidate_dir / target["binary"]
    archive_path = candidate_dir / target["archive"]
    if digest_path(binary_path) != summary["binary_sha256"]:
        fail(f"candidate {target['target']} binary digest mismatch")
    if digest_path(archive_path) != summary["archive_sha256"]:
        fail(f"candidate {target['target']} archive digest mismatch")
    validate_binary_format(binary_path, target["goos"])
    validate_archive(archive_path, target, candidate_dir)
    if not read_bytes(candidate_dir / "help-readback.txt", "help readback", 65536).strip():
        fail(f"candidate {target['target']} help readback is empty")

    version, _ = read_json(
        candidate_dir / "version-readback.json", "version readback", 16384
    )
    if set(version) != {
        "schema_version",
        "version",
        "commit",
        "date",
        "go_version",
        "os",
        "arch",
    }:
        fail(f"candidate {target['target']} version readback fields mismatch")
    version_expected = {
        "schema_version": "covenant.version-result.v1",
        "version": manifest["version"],
        "commit": manifest["source_sha"],
        "date": manifest["build_date"],
        "os": target["goos"],
        "arch": target["goarch"],
    }
    for key, expected in version_expected.items():
        if version.get(key) != expected:
            fail(f"candidate {target['target']} version identity mismatch")
    if not isinstance(version.get("go_version"), str) or not version["go_version"]:
        fail(f"candidate {target['target']} Go version is missing")

    smoke, _ = read_json(
        candidate_dir / "provider-free-smoke.json", "provider-free smoke", 4096
    )
    if smoke != {
        "schema_version": "ao.covenant.provider-free-smoke.v1",
        "status": "passed",
        "provider_credentials_used": False,
        "network_provider_calls_attempted": False,
    }:
        fail(f"candidate {target['target']} provider-free smoke mismatch")
    provenance, _ = read_json(
        candidate_dir / "provenance.json", "candidate provenance", 8192
    )
    if provenance != {
        "schema_version": "ao.covenant.native-candidate-provenance.v1",
        "source_sha": manifest["source_sha"],
        "version": manifest["version"],
        "tag": manifest["tag"],
        "build_date": manifest["build_date"],
        "target": target["target"],
        "runner": target["runner"],
        "approved_manifest_sha256": binding["approved_manifest_sha256"],
    }:
        fail(f"candidate {target['target']} provenance mismatch")
    return summary


def validate_release_dir(release_dir, manifest, summaries):
    release_manifest, _ = read_json(
        release_dir / "manifest.json", "signed release manifest", 65536
    )
    if release_manifest.get("schema_version") != "covenant.release-manifest.v1":
        fail("signed release manifest schema mismatch")
    if (
        release_manifest.get("version") != manifest["version"]
        or release_manifest.get("commit") != manifest["source_sha"]
        or release_manifest.get("date") != manifest["build_date"]
    ):
        fail("signed release manifest identity mismatch")
    artifacts = release_manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(summaries):
        fail("signed release artifact inventory mismatch")
    by_name = {artifact.get("name"): artifact for artifact in artifacts}
    for summary in summaries:
        artifact = by_name.get(summary["binary"])
        if not isinstance(artifact, dict):
            fail("signed release is missing a native candidate")
        if (
            artifact.get("path") != summary["binary"]
            or artifact.get("sha256") != summary["binary_sha256"].removeprefix("sha256:")
            or artifact.get("target")
            != {"os": summary["goos"], "arch": summary["goarch"]}
            or digest_path(release_dir / summary["binary"])
            != summary["binary_sha256"]
        ):
            fail("signed release native candidate substitution")
    verify, _ = read_json(release_dir / "release-verify.json", "release verification")
    report, _ = read_json(release_dir / "release-report.json", "release report")
    if verify.get("verified") is not True:
        fail("release cryptographic verification did not pass")
    if report.get("valid") is not True:
        fail("release cryptographic report did not pass")
    public_key, public_key_bytes = read_json(
        release_dir / "covenant-release-public-key.json", "release public key"
    )
    if "private_key" in public_key or b"private_key" in public_key_bytes:
        fail("release public key contains private material")
    required = {
        *(summary["binary"] for summary in summaries),
        "manifest.json",
        "SHA256SUMS",
        "release-signature.json",
        "covenant-release-public-key.json",
        "release-package.json",
        "release-verify.json",
        "release-report.json",
        "LICENSE",
        "NOTICE",
    }
    observed = {
        path.name
        for path in release_dir.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if observed != required:
        fail("signed release file inventory mismatch")
    if any(path.is_symlink() or not path.is_file() for path in release_dir.iterdir()):
        fail("signed release contains unsafe file types")
    return sorted(
        (
            {
                "name": name,
                "sha256": digest_path(release_dir / name),
                "size_bytes": (release_dir / name).stat().st_size,
            }
            for name in required
        ),
        key=lambda item: item["name"],
    )


def build_promotion_plan(args):
    manifest, _ = validate_manifest(args.approved_manifest)
    binding, _ = read_json(args.binding, "release input binding", 16384)
    binding_expected = {
        "schema_version": "ao.covenant.release-input-binding.v1",
        "status": "passed",
        "source_sha": manifest["source_sha"],
        "version": manifest["version"],
        "tag": manifest["tag"],
        "build_date": manifest["build_date"],
        "approved_manifest_sha256": digest_path(args.approved_manifest),
        "publication_status": "not_attempted",
        "tag_creation_attempted": False,
        "release_creation_attempted": False,
        "public_upload_attempted": False,
    }
    for key, expected in binding_expected.items():
        if binding.get(key) != expected:
            fail(f"release input binding {key} mismatch")
    if set(binding) != set(binding_expected) | {"dry_run", "live_confirmation_verified"}:
        fail("release input binding fields mismatch")

    candidates_dir = pathlib.Path(args.candidates_dir)
    expected_dirs = {target["target"] for target in manifest["targets"]}
    observed_dirs = {
        path.name for path in candidates_dir.iterdir() if path.is_dir()
    }
    if observed_dirs != expected_dirs:
        fail("native candidate directory inventory mismatch")
    if any(not path.is_dir() or path.is_symlink() for path in candidates_dir.iterdir()):
        fail("native candidate root contains unsafe entries")
    summaries = [
        validate_candidate(candidates_dir / target["target"], target, manifest, binding)
        for target in manifest["targets"]
    ]
    assets = validate_release_dir(pathlib.Path(args.release_dir), manifest, summaries)
    plan = {
        "schema_version": "ao.covenant.immutable-promotion-plan.v1",
        "status": "ready",
        "source_sha": manifest["source_sha"],
        "version": manifest["version"],
        "tag": manifest["tag"],
        "build_date": manifest["build_date"],
        "approved_manifest_sha256": binding["approved_manifest_sha256"],
        "candidates": [
            {
                "target": summary["target"],
                "runner": summary["runner"],
                "goos": summary["goos"],
                "goarch": summary["goarch"],
                "binary": summary["binary"],
                "binary_sha256": summary["binary_sha256"],
                "archive": summary["archive"],
                "archive_sha256": summary["archive_sha256"],
            }
            for summary in summaries
        ],
        "release_assets": assets,
        "publication_status": "not_attempted",
        "tag_creation_attempted": False,
        "release_creation_attempted": False,
        "public_upload_attempted": False,
    }
    return manifest, binding, plan


def command_candidates(args):
    _, _, plan = build_promotion_plan(args)
    write_json(args.plan_out, plan)


def command_promotion(args):
    if not SHA_RE.fullmatch(args.expected_source):
        fail("publisher expected source SHA is invalid")
    if (
        not VERSION_RE.fullmatch(args.expected_version)
        or args.expected_tag != args.expected_version
    ):
        fail("publisher expected version or tag is invalid")
    if not DIGEST_RE.fullmatch(args.expected_manifest_digest):
        fail("publisher expected manifest digest is invalid")
    manifest, binding, rebuilt_plan = build_promotion_plan(args)
    if (
        manifest["source_sha"] != args.expected_source
        or manifest["version"] != args.expected_version
        or manifest["tag"] != args.expected_tag
        or digest_path(args.approved_manifest) != args.expected_manifest_digest
    ):
        fail("publisher approved manifest binding mismatch")
    repository_version = read_bytes(
        args.repository_version_file, "publisher repository version", 128
    ).decode("ascii", "strict").strip()
    if repository_version != args.expected_version:
        fail("publisher repository version mismatch")
    expected_confirmation = (
        f"publish:{args.expected_tag}:{args.expected_source}:"
        f"{args.expected_manifest_digest}"
    )
    if args.live_confirmation != expected_confirmation:
        fail("publisher live confirmation mismatch")
    if binding.get("dry_run") is not False:
        fail("publisher input binding is not live")
    if binding.get("live_confirmation_verified") is not True:
        fail("publisher live confirmation binding is not verified")
    supplied_plan, _ = read_json(args.plan, "downloaded promotion plan", 131072)
    if supplied_plan != rebuilt_plan:
        fail("downloaded promotion plan does not match independently rebuilt plan")
    write_json(
        args.out,
        {
            "schema_version": "ao.covenant.publisher-reverification.v1",
            "status": "passed",
            "source_sha": args.expected_source,
            "version": args.expected_version,
            "tag": args.expected_tag,
            "approved_manifest_sha256": args.expected_manifest_digest,
            "candidate_bindings_verified": True,
            "release_asset_digests_verified": True,
            "publication_status": "not_attempted",
            "tag_creation_attempted": False,
            "release_creation_attempted": False,
            "public_upload_attempted": False,
        },
    )


def command_published(args):
    plan, _ = read_json(args.plan, "promotion plan", 131072)
    exact_keys(
        plan,
        {
            "schema_version",
            "status",
            "source_sha",
            "version",
            "tag",
            "build_date",
            "approved_manifest_sha256",
            "candidates",
            "release_assets",
            "publication_status",
            "tag_creation_attempted",
            "release_creation_attempted",
            "public_upload_attempted",
        },
        "promotion plan",
    )
    if (
        plan["schema_version"] != "ao.covenant.immutable-promotion-plan.v1"
        or plan["status"] != "ready"
        or plan["source_sha"] != args.source_sha
        or plan["tag"] != args.tag
    ):
        fail("promotion plan identity mismatch")
    if not SHA_RE.fullmatch(args.source_sha) or plan["version"] != args.tag:
        fail("published source, version, or tag is invalid")
    tag_ref, _ = read_json(args.tag_ref_json, "published tag ref", 16384)
    exact_keys(tag_ref, {"ref", "object"}, "published tag ref")
    if tag_ref["ref"] != f"refs/tags/{args.tag}":
        fail("published tag ref mismatch")
    if tag_ref["object"] != {"type": "commit", "sha": args.source_sha}:
        fail("published tag target mismatch")
    release, _ = read_json(args.release_json, "published release metadata", 65536)
    exact_keys(
        release,
        {"tag_name", "draft", "prerelease", "assets"},
        "published release metadata",
    )
    if (
        release["tag_name"] != args.tag
        or release["draft"] is not False
        or release["prerelease"] is not False
        or not isinstance(release["assets"], list)
    ):
        fail("published release metadata mismatch")
    expected_assets = plan["release_assets"]
    if not isinstance(expected_assets, list) or not expected_assets:
        fail("promotion plan release assets are missing")
    expected_names = []
    for asset in expected_assets:
        if (
            not isinstance(asset, dict)
            or set(asset) != {"name", "sha256", "size_bytes"}
            or not isinstance(asset["name"], str)
            or not DIGEST_RE.fullmatch(asset["sha256"])
            or type(asset["size_bytes"]) is not int
            or asset["size_bytes"] < 0
        ):
            fail("promotion plan release asset is malformed")
        expected_names.append(asset["name"])
    if release["assets"] != [{"name": name} for name in expected_names]:
        fail("published release asset inventory mismatch")
    downloaded = pathlib.Path(args.downloaded_dir)
    observed = {
        path.name
        for path in downloaded.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if observed != set(expected_names):
        fail("downloaded release asset inventory mismatch")
    if any(path.is_symlink() or not path.is_file() for path in downloaded.iterdir()):
        fail("downloaded release contains unsafe file types")
    for asset in expected_assets:
        path = downloaded / asset["name"]
        if (
            digest_path(path) != asset["sha256"]
            or path.stat().st_size != asset["size_bytes"]
        ):
            fail(f"published release asset substitution: {asset['name']}")
    write_json(
        args.out,
        {
            "schema_version": "ao.covenant.published-release-verification.v1",
            "status": "passed",
            "source_sha": args.source_sha,
            "tag": args.tag,
            "tag_target_sha": tag_ref["object"]["sha"],
            "asset_count": len(expected_assets),
            "asset_digests_verified": True,
        },
    )


def parser():
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command", required=True)
    inputs = subparsers.add_parser("inputs")
    inputs.add_argument("--manifest", required=True)
    inputs.add_argument("--expected-digest", required=True)
    inputs.add_argument("--expected-source", required=True)
    inputs.add_argument("--expected-version", required=True)
    inputs.add_argument("--expected-tag", required=True)
    inputs.add_argument("--repository-version-file", required=True)
    inputs.add_argument("--dry-run", required=True)
    inputs.add_argument("--live-confirmation", default="")
    inputs.add_argument("--out", required=True)
    inputs.set_defaults(handler=command_inputs)
    candidates = subparsers.add_parser("candidates")
    candidates.add_argument("--candidates-dir", required=True)
    candidates.add_argument("--approved-manifest", required=True)
    candidates.add_argument("--binding", required=True)
    candidates.add_argument("--release-dir", required=True)
    candidates.add_argument("--plan-out", required=True)
    candidates.set_defaults(handler=command_candidates)
    promotion = subparsers.add_parser("promotion")
    promotion.add_argument("--candidates-dir", required=True)
    promotion.add_argument("--approved-manifest", required=True)
    promotion.add_argument("--binding", required=True)
    promotion.add_argument("--release-dir", required=True)
    promotion.add_argument("--plan", required=True)
    promotion.add_argument("--expected-source", required=True)
    promotion.add_argument("--expected-version", required=True)
    promotion.add_argument("--expected-tag", required=True)
    promotion.add_argument("--expected-manifest-digest", required=True)
    promotion.add_argument("--repository-version-file", required=True)
    promotion.add_argument("--live-confirmation", required=True)
    promotion.add_argument("--out", required=True)
    promotion.set_defaults(handler=command_promotion)
    published = subparsers.add_parser("published")
    published.add_argument("--plan", required=True)
    published.add_argument("--source-sha", required=True)
    published.add_argument("--tag", required=True)
    published.add_argument("--tag-ref-json", required=True)
    published.add_argument("--release-json", required=True)
    published.add_argument("--downloaded-dir", required=True)
    published.add_argument("--out", required=True)
    published.set_defaults(handler=command_published)
    return root


def main():
    args = parser().parse_args()
    try:
        args.handler(args)
    except (VerificationError, OSError, UnicodeError) as error:
        print(f"release modernization verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
