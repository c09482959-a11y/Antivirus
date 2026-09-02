"""Immutable scan-session manifest publication for filesystem queue workers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import time

from Virus_Scan.contracts.scan_session_snapshot import (
    ScanSessionSnapshot,
    scan_session_snapshot_from_record,
)
from Virus_Scan.runtime.api import flush_open_writable_file
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_atomic_replace, queue_safe_unlink

SCAN_SESSION_MANIFEST_FILENAME = "scan_session_snapshot.json"
_SCAN_SESSION_MANIFEST_MAX_BYTES = 1_048_576


def _exact_manifest_path(value: object, reason: str) -> Path:
    text, rejected = scheduler_path_text(value)
    if rejected or text == "":
        raise ValueError(reason)
    return Path(text)


def scan_session_manifest_path(runtime_dir: object) -> Path:
    """Return the unique manifest path for one process-queue runtime directory."""
    root = _exact_manifest_path(runtime_dir, "scan_session_manifest_runtime_dir_rejected")
    return root / SCAN_SESSION_MANIFEST_FILENAME


def _load_manifest_record(path: Path) -> dict[str, object]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        exc.add_note("scan_session_manifest_stat_failed")
        raise RuntimeError("scan_session_manifest_unavailable") from exc
    if size <= 0 or size > _SCAN_SESSION_MANIFEST_MAX_BYTES:
        raise RuntimeError("scan_session_manifest_size_rejected")
    try:
        with path.open("r", encoding="utf-8", errors="strict") as handle:
            loaded = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        exc.add_note("scan_session_manifest_read_failed")
        raise RuntimeError("scan_session_manifest_invalid") from exc
    if type(loaded) is not dict:
        raise RuntimeError("scan_session_manifest_invalid")
    return loaded


def read_scan_session_manifest(path: object) -> ScanSessionSnapshot:
    """Read and validate one exact current-schema immutable session manifest."""
    manifest_path = _exact_manifest_path(path, "scan_session_manifest_path_rejected")
    try:
        return scan_session_snapshot_from_record(_load_manifest_record(manifest_path))
    except (TypeError, ValueError) as exc:
        exc.add_note("scan_session_manifest_invalid")
        raise RuntimeError("scan_session_manifest_invalid") from exc


def _write_manifest_tmp(tmp: Path, record: dict[str, object]) -> None:
    with tmp.open("x", encoding="utf-8", errors="strict") as handle:
        json.dump(
            record,
            handle,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        handle.flush()
        flush_open_writable_file(handle.fileno())


def publish_scan_session_manifest(
    runtime_dir: object,
    snapshot: object,
) -> Path:
    """Atomically publish and verify the parent-approved session generation."""
    if type(snapshot) is not ScanSessionSnapshot:
        raise TypeError("scan_session_manifest_snapshot_required")
    target = scan_session_manifest_path(runtime_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(
        target.name + ".tmp-" + int.__str__(os.getpid()) + "-" + int.__str__(time.time_ns())
    )
    record = snapshot.to_record()
    try:
        _write_manifest_tmp(tmp, record)
        staged = read_scan_session_manifest(tmp)
        if staged.to_record() != record:
            raise RuntimeError("scan_session_manifest_staged_mismatch")
        if not queue_atomic_replace(tmp, target, log_context="scan_session_manifest"):
            raise RuntimeError("scan_session_manifest_publication_failed")
        published = read_scan_session_manifest(target)
        if published.to_record() != record:
            raise RuntimeError("scan_session_manifest_verification_mismatch")
        return target
    finally:
        if tmp.exists():
            queue_safe_unlink(tmp, log_context="scan_session_manifest_tmp_cleanup")


__all__ = (
    "SCAN_SESSION_MANIFEST_FILENAME",
    "publish_scan_session_manifest",
    "read_scan_session_manifest",
    "scan_session_manifest_path",
)
