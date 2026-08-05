#!/usr/bin/env python3
"""Restore executable bits stripped by GitHub artifact transport."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any


MAX_PLAN_BYTES = 64 * 1024
SUPPORTED_GOOS = {"darwin", "linux", "windows"}


class RestoreError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RestoreError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_plan(path: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RestoreError(f"plan metadata read failed: {exc}") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise RestoreError("plan must be a regular non-symlink file")
    if info.st_size > MAX_PLAN_BYTES:
        raise RestoreError(f"plan exceeds {MAX_PLAN_BYTES} bytes")
    try:
        raw = path.read_bytes()
        plan = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RestoreError(f"plan read failed: {exc}") from exc
    if not isinstance(plan, dict):
        raise RestoreError("plan root must be an object")
    return plan


def candidate_inventory(plan: dict[str, Any]) -> list[tuple[str, str]]:
    candidates = plan.get("candidates")
    if not isinstance(candidates, list) or not candidates:
        raise RestoreError("plan candidates must be a non-empty array")

    inventory: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            raise RestoreError(f"candidate {index} must be an object")
        binary = candidate.get("binary")
        goos = candidate.get("goos")
        if not isinstance(binary, str) or not binary:
            raise RestoreError(f"candidate {index} binary must be a non-empty string")
        if (
            binary in {".", ".."}
            or Path(binary).is_absolute()
            or "/" in binary
            or "\\" in binary
            or Path(binary).name != binary
        ):
            raise RestoreError(f"candidate {index} binary is not a safe basename")
        if binary in seen:
            raise RestoreError(f"duplicate candidate binary: {binary}")
        if not isinstance(goos, str) or goos not in SUPPORTED_GOOS:
            raise RestoreError(f"candidate {index} has unsupported goos")
        seen.add(binary)
        inventory.append((binary, goos))
    return inventory


def restore(plan_path: Path, release_dir: Path) -> dict[str, Any]:
    try:
        directory_info = release_dir.lstat()
    except OSError as exc:
        raise RestoreError(f"release directory metadata read failed: {exc}") from exc
    if not stat.S_ISDIR(directory_info.st_mode) or release_dir.is_symlink():
        raise RestoreError("release directory must be a non-symlink directory")

    restored: list[str] = []
    unchanged: list[str] = []
    for binary, goos in candidate_inventory(load_plan(plan_path)):
        candidate_path = release_dir / binary
        try:
            candidate_info = candidate_path.lstat()
        except OSError as exc:
            raise RestoreError(f"candidate {binary} metadata read failed: {exc}") from exc
        if not stat.S_ISREG(candidate_info.st_mode) or candidate_path.is_symlink():
            raise RestoreError(f"candidate {binary} must be a regular non-symlink file")
        if goos == "windows":
            unchanged.append(binary)
            continue
        new_mode = stat.S_IMODE(candidate_info.st_mode) | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        try:
            os.chmod(candidate_path, new_mode, follow_symlinks=False)
        except OSError as exc:
            raise RestoreError(f"candidate {binary} mode restore failed: {exc}") from exc
        restored.append(binary)

    return {
        "schema_version": "ao.covenant.executable-mode-restoration.v1",
        "status": "passed",
        "restored": restored,
        "unchanged": unchanged,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--release-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = restore(args.plan, args.release_dir)
    except RestoreError as exc:
        print(f"executable mode restoration failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
