#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import pathlib
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify-release-modernization.py"
SOURCE = "a" * 40
VERSION = "v0.1.0"
TAG = VERSION
BUILD_DATE = "2026-07-20T00:00:00Z"
TARGETS = (
    ("linux-amd64", "ubuntu-latest", "linux", "amd64"),
    ("darwin-amd64", "macos-15-intel", "darwin", "amd64"),
    ("windows-amd64", "windows-latest", "windows", "amd64"),
)


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def approved_manifest():
    targets = []
    for label, runner, goos, goarch in TARGETS:
        binary = f"ao-covenant_{VERSION}_{goos}_{goarch}"
        if goos == "windows":
            binary += ".exe"
        extension = "zip" if goos == "windows" else "tar.gz"
        targets.append(
            {
                "target": label,
                "runner": runner,
                "goos": goos,
                "goarch": goarch,
                "binary": binary,
                "archive": f"ao-covenant_{VERSION}_{label}.{extension}",
            }
        )
    return {
        "schema_version": "ao.covenant.release-approved-manifest.v1",
        "repository": "uesugitorachiyo/ao-covenant",
        "source_sha": SOURCE,
        "version": VERSION,
        "tag": TAG,
        "build_date": BUILD_DATE,
        "targets": targets,
        "required_package_files": ["LICENSE", "NOTICE"],
        "safety_boundaries": {
            "provider_credentials_allowed": False,
            "network_provider_calls_allowed": False,
            "public_mutation_allowed": False,
            "inbound_service_allowed": False,
            "arbitrary_remote_command_allowed": False,
        },
    }


def fake_binary(goos):
    if goos == "linux":
        data = bytearray(128)
        data[:4] = b"\x7fELF"
        data[4] = 2
        data[5] = 1
        data[18:20] = struct.pack("<H", 62)
        return bytes(data)
    if goos == "darwin":
        return struct.pack("<IIII", 0xFEEDFACF, 0x01000007, 3, 2) + bytes(112)
    data = bytearray(256)
    data[:2] = b"MZ"
    data[0x3C:0x40] = struct.pack("<I", 0x80)
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = struct.pack("<H", 0x8664)
    return bytes(data)


def write_regular_zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as handle:
        for name, data, permissions in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | permissions) << 16
            handle.writestr(info, data)


class ReleaseModernizationTest(unittest.TestCase):
    def setUp(self):
        self.temp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.temp))
        self.version_file = self.temp / "VERSION"
        self.version_file.write_text(VERSION + "\n")
        self.manifest = self.temp / "approved-manifest.json"
        self.write_manifest(approved_manifest())
        self.binding = self.temp / "binding.json"

    def write_manifest(self, value):
        self.manifest.write_bytes(canonical_json(value))
        self.digest = "sha256:" + sha256(self.manifest.read_bytes())

    def run_verify(self, mode, *args, expect=0):
        completed = subprocess.run(
            [sys.executable, str(VERIFIER), mode, *map(str, args)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(
            completed.returncode,
            expect,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def input_args(self, **overrides):
        values = {
            "manifest": self.manifest,
            "expected_digest": self.digest,
            "expected_source": SOURCE,
            "expected_version": VERSION,
            "expected_tag": TAG,
            "repository_version_file": self.version_file,
            "dry_run": "true",
            "live_confirmation": "",
            "out": self.binding,
        }
        values.update(overrides)
        args = []
        for key, value in values.items():
            args.extend(("--" + key.replace("_", "-"), value))
        return args

    def validate_inputs(self, **overrides):
        return self.run_verify("inputs", *self.input_args(**overrides))

    def test_valid_inputs_are_bound_without_publication_authority(self):
        self.validate_inputs()
        binding = json.loads(self.binding.read_text())
        self.assertEqual(binding["source_sha"], SOURCE)
        self.assertEqual(binding["approved_manifest_sha256"], self.digest)
        self.assertEqual(binding["publication_status"], "not_attempted")
        self.assertFalse(binding["tag_creation_attempted"])
        self.assertFalse(binding["release_creation_attempted"])
        self.assertFalse(binding["public_upload_attempted"])

    def test_rejects_altered_digest(self):
        self.run_verify(
            "inputs",
            *self.input_args(expected_digest="sha256:" + "b" * 64),
            expect=1,
        )

    def test_rejects_wrong_source_head(self):
        self.run_verify(
            "inputs",
            *self.input_args(expected_source="b" * 40),
            expect=1,
        )

    def test_rejects_wrong_version_or_tag(self):
        for override in (
            {"expected_version": "v9.9.9"},
            {"expected_tag": "v9.9.9"},
        ):
            with self.subTest(override=override):
                self.run_verify("inputs", *self.input_args(**override), expect=1)

    def test_rejects_malformed_or_oversized_manifest(self):
        self.manifest.write_text("{")
        self.run_verify("inputs", *self.input_args(), expect=1)
        self.manifest.write_bytes(b" " * 32769)
        self.run_verify("inputs", *self.input_args(), expect=1)

    def test_rejects_unknown_fields_and_unsafe_boundaries(self):
        value = approved_manifest()
        value["unexpected"] = True
        self.write_manifest(value)
        self.run_verify("inputs", *self.input_args(), expect=1)

        value = approved_manifest()
        value["safety_boundaries"]["public_mutation_allowed"] = True
        self.write_manifest(value)
        self.run_verify("inputs", *self.input_args(), expect=1)

    def test_live_confirmation_is_exact(self):
        confirmation = f"publish:{TAG}:{SOURCE}:{self.digest}"
        self.validate_inputs(dry_run="false", live_confirmation=confirmation)
        self.run_verify(
            "inputs",
            *self.input_args(dry_run="false", live_confirmation="publish"),
            expect=1,
        )

    def make_candidates(self):
        self.validate_inputs()
        root = self.temp / "candidates"
        if root.exists():
            shutil.rmtree(root)
        root.mkdir()
        manifest = approved_manifest()
        license_bytes = b"license\n"
        notice_bytes = b"notice\n"
        for target in manifest["targets"]:
            candidate = root / target["target"]
            candidate.mkdir()
            binary_bytes = fake_binary(target["goos"])
            (candidate / target["binary"]).write_bytes(binary_bytes)
            (candidate / "LICENSE").write_bytes(license_bytes)
            (candidate / "NOTICE").write_bytes(notice_bytes)
            archive = candidate / target["archive"]
            if target["goos"] == "windows":
                write_regular_zip(
                    archive,
                    (
                        (target["binary"], binary_bytes, 0o755),
                        ("LICENSE", license_bytes, 0o644),
                        ("NOTICE", notice_bytes, 0o644),
                    ),
                )
            else:
                with tarfile.open(archive, "w:gz") as handle:
                    for name, data in (
                        (target["binary"], binary_bytes),
                        ("LICENSE", license_bytes),
                        ("NOTICE", notice_bytes),
                    ):
                        path = candidate / name
                        handle.add(path, arcname=name, recursive=False)
            evidence = {
                "help-readback.txt": b"AO Covenant\n",
                "version-readback.json": canonical_json(
                    {
                        "schema_version": "covenant.version-result.v1",
                        "version": VERSION,
                        "commit": SOURCE,
                        "date": BUILD_DATE,
                        "go_version": "go1.26.4",
                        "os": target["goos"],
                        "arch": target["goarch"],
                    }
                ),
                "provider-free-smoke.json": canonical_json(
                    {
                        "schema_version": "ao.covenant.provider-free-smoke.v1",
                        "status": "passed",
                        "provider_credentials_used": False,
                        "network_provider_calls_attempted": False,
                    }
                ),
                "provenance.json": canonical_json(
                    {
                        "schema_version": "ao.covenant.native-candidate-provenance.v1",
                        "source_sha": SOURCE,
                        "version": VERSION,
                        "tag": TAG,
                        "build_date": BUILD_DATE,
                        "target": target["target"],
                        "runner": target["runner"],
                        "approved_manifest_sha256": self.digest,
                    }
                ),
            }
            for name, data in evidence.items():
                (candidate / name).write_bytes(data)
            summary = {
                "schema_version": "ao.covenant.native-release-candidate.v1",
                "status": "passed",
                "source_sha": SOURCE,
                "version": VERSION,
                "tag": TAG,
                "build_date": BUILD_DATE,
                "target": target["target"],
                "runner": target["runner"],
                "goos": target["goos"],
                "goarch": target["goarch"],
                "binary": target["binary"],
                "binary_sha256": "sha256:" + sha256(binary_bytes),
                "archive": target["archive"],
                "archive_sha256": "sha256:" + sha256(archive.read_bytes()),
                "approved_manifest_sha256": self.digest,
                "help_status": "passed",
                "version_source_status": "passed",
                "provider_free_status": "passed",
                "provider_credentials_used": False,
                "network_provider_calls_attempted": False,
            }
            (candidate / "candidate-summary.json").write_bytes(canonical_json(summary))
            checksums = []
            for path in sorted(candidate.iterdir()):
                if path.name != "SHA256SUMS":
                    checksums.append(f"{sha256(path.read_bytes())}  {path.name}\n")
            (candidate / "SHA256SUMS").write_text("".join(checksums))
        return root

    def rewrite_candidate_checksums(self, candidate):
        checksums = []
        for path in sorted(candidate.iterdir()):
            if path.name != "SHA256SUMS":
                checksums.append(f"{sha256(path.read_bytes())}  {path.name}\n")
        (candidate / "SHA256SUMS").write_text("".join(checksums))

    def rebind_windows_archive(self, candidates, entries):
        candidate = candidates / "windows-amd64"
        archive = candidate / f"ao-covenant_{VERSION}_windows-amd64.zip"
        write_regular_zip(archive, entries)
        summary_path = candidate / "candidate-summary.json"
        summary = json.loads(summary_path.read_text())
        summary["archive_sha256"] = "sha256:" + sha256(archive.read_bytes())
        summary_path.write_bytes(canonical_json(summary))
        self.rewrite_candidate_checksums(candidate)

    def candidate_args(self, candidates, **overrides):
        values = {
            "candidates_dir": candidates,
            "approved_manifest": self.manifest,
            "binding": self.binding,
            "release_dir": self.temp / "release",
            "plan_out": self.temp / "promotion-plan.json",
        }
        values.update(overrides)
        args = []
        for key, value in values.items():
            args.extend(("--" + key.replace("_", "-"), value))
        return args

    def make_release_dir(self, candidates):
        release = self.temp / "release"
        if release.exists():
            shutil.rmtree(release)
        release.mkdir()
        manifest = approved_manifest()
        artifacts = []
        for target in manifest["targets"]:
            source = candidates / target["target"] / target["binary"]
            destination = release / target["binary"]
            shutil.copyfile(source, destination)
            artifacts.append(
                {
                    "name": target["binary"],
                    "target": {"os": target["goos"], "arch": target["goarch"]},
                    "path": target["binary"],
                    "sha256": sha256(destination.read_bytes()),
                    "size_bytes": destination.stat().st_size,
                }
            )
        release_manifest = {
            "schema_version": "covenant.release-manifest.v1",
            "version": VERSION,
            "commit": SOURCE,
            "date": BUILD_DATE,
            "artifacts": artifacts,
        }
        (release / "manifest.json").write_bytes(canonical_json(release_manifest))
        for name, data in (
            ("LICENSE", b"license\n"),
            ("NOTICE", b"notice\n"),
            ("covenant-release-public-key.json", b'{"public_key":"test"}\n'),
            ("release-signature.json", b'{"signature":"test"}\n'),
            ("release-package.json", b'{"schema_version":"test"}\n'),
            ("release-verify.json", b'{"verified":true}\n'),
            ("release-report.json", b'{"valid":true}\n'),
        ):
            (release / name).write_bytes(data)
        checksum_entries = []
        for artifact in artifacts:
            checksum_entries.append(f"{artifact['sha256']}  {artifact['name']}\n")
        (release / "SHA256SUMS").write_text("".join(checksum_entries))
        return release

    def test_valid_native_candidates_create_immutable_plan(self):
        candidates = self.make_candidates()
        self.make_release_dir(candidates)
        self.run_verify("candidates", *self.candidate_args(candidates))
        plan = json.loads((self.temp / "promotion-plan.json").read_text())
        self.assertEqual(plan["status"], "ready")
        self.assertEqual(len(plan["candidates"]), 3)
        self.assertEqual(plan["publication_status"], "not_attempted")

    def test_rejects_candidate_digest_identity_and_smoke_substitution(self):
        mutations = ("digest", "source", "version", "smoke")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidates = self.make_candidates()
                self.make_release_dir(candidates)
                summary_path = candidates / "linux-amd64" / "candidate-summary.json"
                summary = json.loads(summary_path.read_text())
                if mutation == "digest":
                    summary["binary_sha256"] = "sha256:" + "b" * 64
                elif mutation == "source":
                    summary["source_sha"] = "b" * 40
                elif mutation == "version":
                    summary["version"] = "v9.9.9"
                else:
                    summary["provider_free_status"] = "failed"
                summary_path.write_bytes(canonical_json(summary))
                self.run_verify(
                    "candidates", *self.candidate_args(candidates), expect=1
                )

    def test_rejects_malformed_extra_and_unsafe_archive_entries(self):
        candidates = self.make_candidates()
        self.make_release_dir(candidates)
        (candidates / "linux-amd64" / "candidate-summary.json").write_text("{")
        self.run_verify("candidates", *self.candidate_args(candidates), expect=1)

        candidates = self.make_candidates()
        self.make_release_dir(candidates)
        (candidates / "linux-amd64" / "extra.txt").write_text("extra")
        self.run_verify("candidates", *self.candidate_args(candidates), expect=1)

        candidates = self.make_candidates()
        self.make_release_dir(candidates)
        archive = candidates / "linux-amd64" / f"ao-covenant_{VERSION}_linux-amd64.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            unsafe = self.temp / "unsafe"
            unsafe.write_text("unsafe")
            handle.add(unsafe, arcname="../unsafe", recursive=False)
        self.run_verify("candidates", *self.candidate_args(candidates), expect=1)

    def test_rejects_release_binary_substitution(self):
        candidates = self.make_candidates()
        release = self.make_release_dir(candidates)
        binary = release / f"ao-covenant_{VERSION}_linux_amd64"
        binary.write_bytes(b"substituted")
        self.run_verify("candidates", *self.candidate_args(candidates), expect=1)

    def test_rejects_rebound_windows_zip_non_regular_entry_types(self):
        type_modes = {
            "symlink": stat.S_IFLNK | 0o777,
            "character-device": stat.S_IFCHR | 0o600,
            "block-device": stat.S_IFBLK | 0o600,
            "fifo": stat.S_IFIFO | 0o600,
            "socket": stat.S_IFSOCK | 0o600,
            "directory": stat.S_IFDIR | 0o755,
        }
        for name, mode in type_modes.items():
            with self.subTest(entry_type=name):
                candidates = self.make_candidates()
                self.make_release_dir(candidates)
                binary_name = f"ao-covenant_{VERSION}_windows_amd64.exe"
                archive = (
                    candidates
                    / "windows-amd64"
                    / f"ao-covenant_{VERSION}_windows-amd64.zip"
                )
                with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
                    for entry_name, data, entry_mode in (
                        (binary_name, fake_binary("windows"), mode),
                        ("LICENSE", b"license\n", stat.S_IFREG | 0o644),
                        ("NOTICE", b"notice\n", stat.S_IFREG | 0o644),
                    ):
                        info = zipfile.ZipInfo(entry_name)
                        info.create_system = 3
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.external_attr = entry_mode << 16
                        handle.writestr(info, data)
                summary_path = (
                    candidates / "windows-amd64" / "candidate-summary.json"
                )
                summary = json.loads(summary_path.read_text())
                summary["archive_sha256"] = "sha256:" + sha256(archive.read_bytes())
                summary_path.write_bytes(canonical_json(summary))
                self.rewrite_candidate_checksums(candidates / "windows-amd64")
                self.run_verify(
                    "candidates", *self.candidate_args(candidates), expect=1
                )

    def test_rejects_rebound_windows_zip_unsafe_path_forms(self):
        unsafe_names = (
            "nested/file.exe",
            "../escape.exe",
            "/absolute.exe",
            "C:/drive.exe",
            r"C:\drive.exe",
            r"\\server\share.exe",
            "//server/share.exe",
        )
        for unsafe_name in unsafe_names:
            with self.subTest(unsafe_name=unsafe_name):
                candidates = self.make_candidates()
                self.make_release_dir(candidates)
                self.rebind_windows_archive(
                    candidates,
                    (
                        (unsafe_name, fake_binary("windows"), 0o755),
                        ("LICENSE", b"license\n", 0o644),
                        ("NOTICE", b"notice\n", 0o644),
                    ),
                )
                self.run_verify(
                    "candidates", *self.candidate_args(candidates), expect=1
                )

    def promotion_args(self, candidates, **overrides):
        values = {
            "candidates_dir": candidates,
            "approved_manifest": self.manifest,
            "binding": self.binding,
            "release_dir": self.temp / "release",
            "plan": self.temp / "promotion-plan.json",
            "expected_source": SOURCE,
            "expected_version": VERSION,
            "expected_tag": TAG,
            "expected_manifest_digest": self.digest,
            "repository_version_file": self.version_file,
            "live_confirmation": f"publish:{TAG}:{SOURCE}:{self.digest}",
            "out": self.temp / "publisher-verification.json",
        }
        values.update(overrides)
        args = []
        for key, value in values.items():
            args.extend(("--" + key.replace("_", "-"), value))
        return args

    def promotion_fixture(self):
        self.validate_inputs(
            dry_run="false",
            live_confirmation=f"publish:{TAG}:{SOURCE}:{self.digest}",
        )
        candidates = self.make_candidates()
        self.validate_inputs(
            dry_run="false",
            live_confirmation=f"publish:{TAG}:{SOURCE}:{self.digest}",
        )
        self.make_release_dir(candidates)
        self.run_verify("candidates", *self.candidate_args(candidates))
        return candidates

    def test_valid_promotion_bundle_is_fully_reverified(self):
        candidates = self.promotion_fixture()
        self.run_verify("promotion", *self.promotion_args(candidates))
        result = json.loads((self.temp / "publisher-verification.json").read_text())
        self.assertEqual(result["status"], "passed")
        self.assertTrue(result["candidate_bindings_verified"])
        self.assertTrue(result["release_asset_digests_verified"])

    def test_promotion_reverification_rejects_bypass_mutations(self):
        for mutation in (
            "plan-source",
            "plan-asset-digest",
            "binding-source",
            "candidate-binding",
            "failed-signature-report",
        ):
            with self.subTest(mutation=mutation):
                candidates = self.promotion_fixture()
                plan_path = self.temp / "promotion-plan.json"
                if mutation.startswith("plan-"):
                    plan = json.loads(plan_path.read_text())
                    if mutation == "plan-source":
                        plan["source_sha"] = "b" * 40
                    else:
                        plan["release_assets"][0]["sha256"] = "sha256:" + "b" * 64
                    plan_path.write_bytes(canonical_json(plan))
                elif mutation == "binding-source":
                    binding = json.loads(self.binding.read_text())
                    binding["source_sha"] = "b" * 40
                    self.binding.write_bytes(canonical_json(binding))
                elif mutation == "candidate-binding":
                    summary_path = candidates / "linux-amd64" / "candidate-summary.json"
                    summary = json.loads(summary_path.read_text())
                    summary["approved_manifest_sha256"] = "sha256:" + "b" * 64
                    summary_path.write_bytes(canonical_json(summary))
                    self.rewrite_candidate_checksums(candidates / "linux-amd64")
                else:
                    verify_path = self.temp / "release" / "release-verify.json"
                    verify = json.loads(verify_path.read_text())
                    verify["verified"] = False
                    verify_path.write_bytes(canonical_json(verify))
                    plan = json.loads(plan_path.read_text())
                    for asset in plan["release_assets"]:
                        if asset["name"] == "release-verify.json":
                            asset["sha256"] = "sha256:" + sha256(
                                verify_path.read_bytes()
                            )
                            asset["size_bytes"] = verify_path.stat().st_size
                    plan_path.write_bytes(canonical_json(plan))
                self.run_verify(
                    "promotion", *self.promotion_args(candidates), expect=1
                )

    def published_fixture(self):
        candidates = self.make_candidates()
        release = self.make_release_dir(candidates)
        plan_path = self.temp / "promotion-plan.json"
        self.run_verify("candidates", *self.candidate_args(candidates))
        plan = json.loads(plan_path.read_text())
        tag_ref = self.temp / "tag-ref.json"
        tag_ref.write_bytes(
            canonical_json(
                {
                    "ref": f"refs/tags/{TAG}",
                    "object": {"type": "commit", "sha": SOURCE},
                }
            )
        )
        release_json = self.temp / "release.json"
        release_json.write_bytes(
            canonical_json(
                {
                    "tag_name": TAG,
                    "draft": False,
                    "prerelease": False,
                    "assets": [{"name": asset["name"]} for asset in plan["release_assets"]],
                }
            )
        )
        return release, plan_path, tag_ref, release_json

    def published_args(self, release, plan, tag_ref, release_json):
        return (
            "--plan",
            plan,
            "--source-sha",
            SOURCE,
            "--tag",
            TAG,
            "--tag-ref-json",
            tag_ref,
            "--release-json",
            release_json,
            "--downloaded-dir",
            release,
            "--out",
            self.temp / "published-verification.json",
        )

    def test_valid_published_release_is_independently_verified(self):
        release, plan, tag_ref, release_json = self.published_fixture()
        self.run_verify(
            "published", *self.published_args(release, plan, tag_ref, release_json)
        )
        result = json.loads((self.temp / "published-verification.json").read_text())
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["tag_target_sha"], SOURCE)

    def test_rejects_published_tag_or_asset_substitution(self):
        release, plan, tag_ref, release_json = self.published_fixture()
        tag_value = json.loads(tag_ref.read_text())
        tag_value["object"]["sha"] = "b" * 40
        tag_ref.write_bytes(canonical_json(tag_value))
        self.run_verify(
            "published",
            *self.published_args(release, plan, tag_ref, release_json),
            expect=1,
        )

        release, plan, tag_ref, release_json = self.published_fixture()
        release_value = json.loads(release_json.read_text())
        release_value["assets"].pop()
        release_json.write_bytes(canonical_json(release_value))
        self.run_verify(
            "published",
            *self.published_args(release, plan, tag_ref, release_json),
            expect=1,
        )


if __name__ == "__main__":
    unittest.main()
