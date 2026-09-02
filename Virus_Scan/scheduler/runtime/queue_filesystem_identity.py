"""Scheduler queue file identity and workload-weight helpers."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.runtime.api import record_suppressed_failure, scan_integrity_state
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_int,
    scheduler_text,
)
from Virus_Scan.scheduler.runtime.queue_filesystem_common import (
    QUEUE_FILESYSTEM_EXCEPTIONS,
    path_key,
    queue_filesystem_path_text,
)

REJECTED_PROCESS_WEIGHT = 1.0
RAW_STAGE_CACHE_UNAVAILABLE = None


def _record_identity_failure(stage: str, reason: str, value: object) -> None:
    record_suppressed_failure(
        stage,
        ValueError(reason),
        domain="scheduler",
        context={
            "reason": reason,
            "value_type": no_hook_type_name(value),
        },
        fatal=True,
    )


def clear_scan_integrity(path: object) -> None:
    scan_integrity_state().clear(path_key(path))


def set_scan_integrity(path: object, meta: object) -> None:
    items = no_hook_mapping_items(meta)
    if meta is not None and items is None:
        _record_identity_failure(
            "scan_integrity_metadata_rejected",
            "scan_integrity_metadata_not_exact_mapping",
            meta,
        )
        snapshot = {
            "scan_integrity_unavailable": True,
            "scan_integrity_unavailable_reason": "scan_integrity_metadata_not_exact_mapping",
            "scan_integrity_metadata_type": no_hook_type_name(meta),
        }
    else:
        snapshot = dict(items) if items is not None else {}
    scan_integrity_state().set(path_key(path), snapshot)


def global_raw_file_id(path: object) -> str:
    safe_path, path_reason = queue_filesystem_path_text(path)
    if path_reason:
        _record_identity_failure("global_raw_file_id_path_rejected", path_reason, path)
        base = ":".join(("rejected", no_hook_type_name(path), path_reason))
        return hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()[:24]
    try:
        st = os.stat(safe_path)
        base = "|".join((str(Path(safe_path).resolve()), int.__str__(st.st_size), int.__str__(st.st_mtime_ns)))
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        record_suppressed_failure(
            "global_raw_file_id_stat_unavailable",
            exc,
            domain="scheduler",
            context={"path_type": no_hook_type_name(path)},
            fatal=False,
        )
        base = str(Path(safe_path).resolve())
    return hashlib.sha256(base.encode("utf-8", errors="ignore")).hexdigest()[:24]


def process_weight_for_path(path: object) -> float:
    """Heuristic cost used only for ordering scheduler process-queue jobs."""
    safe_path, path_reason = queue_filesystem_path_text(path)
    if path_reason:
        _record_identity_failure("process_weight_path_rejected", path_reason, path)
        return REJECTED_PROCESS_WEIGHT
    try:
        p = Path(safe_path)
        ext = p.suffix.lower()
        size = max(1, int(p.stat().st_size)) if p.exists() else 1
        size_mb = size / (1024.0 * 1024.0)
        if ext in {".exe", ".dll", ".sys", ".ocx", ".scr", ".com", ".so", ".dylib", ".bin", ".elf"}:
            base = 16.0
        elif ext in {".py", ".pyc", ".pyo", ".rpy", ".rpyc", ".rpyb", ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd", ".vbs", ".hta", ".rb", ".sh", ".lua", ".cs"}:
            base = 12.0
        elif ext in {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".rpa", ".jar", ".pak"}:
            base = 14.0
        elif ext in {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".svg", ".ico", ".icns", ".mp3", ".ogg", ".wav", ".flac", ".mp4", ".avi", ".ttf", ".otf"}:
            base = 8.0
        else:
            base = 5.0
        if ext in {".rpyc", ".rpyb", ".rpymc", ".pyc"}:
            base += 10.0
        if ext in {".png", ".webp", ".jpg", ".jpeg"}:
            base += 6.0
        return base + min(128.0, size_mb)
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        record_suppressed_failure(
            "process_weight_path_probe_failed",
            exc,
            domain="scheduler",
            context={"path_type": no_hook_type_name(path)},
            fatal=True,
        )
        return REJECTED_PROCESS_WEIGHT


def queue_file_identity_for_path(file_path: object) -> str:
    safe_path, path_reason = queue_filesystem_path_text(file_path)
    if path_reason:
        _record_identity_failure("queue_file_identity_path_rejected", path_reason, file_path)
        f_key = ":".join(("rejected", no_hook_type_name(file_path), path_reason))
    else:
        f_key = os.path.normcase(str(Path(safe_path).resolve()))
    return hashlib.sha256(f_key.encode("utf-8", "surrogatepass")).hexdigest()[:32]


def raw_stage_cache_key(job: object) -> object:
    items = no_hook_mapping_items(job)
    if items is None:
        _record_identity_failure(
            "raw_stage_cache_job_rejected",
            "raw_stage_cache_job_not_exact_mapping",
            job,
        )
        return RAW_STAGE_CACHE_UNAVAILABLE
    data = dict(items)
    file_text, file_reason = scheduler_text(
        dict.get(data, "file"),
        replacement_text="",
        unsupported_reason="raw_stage_cache_file_rejected",
    )
    collector, collector_reason = scheduler_text(
        dict.get(data, "collector"),
        replacement_text="",
        unsupported_reason="raw_stage_cache_collector_rejected",
    )
    start, start_reason = scheduler_int(
        dict.get(data, "start"),
        default=0,
        minimum=0,
        reason="raw_stage_cache_start_rejected",
    )
    size, size_reason = scheduler_int(
        dict.get(data, "size"),
        default=0,
        minimum=0,
        reason="raw_stage_cache_size_rejected",
    )
    boundary_reason = file_reason or collector_reason or start_reason or size_reason
    if boundary_reason or file_text == "":
        _record_identity_failure(
            "raw_stage_cache_boundary_rejected",
            boundary_reason or "raw_stage_cache_file_missing",
            job,
        )
        return RAW_STAGE_CACHE_UNAVAILABLE
    path = file_text
    try:
        path = str(Path(file_text).resolve())
        st = os.stat(path)
        return (
            path,
            st.st_size,
            st.st_mtime_ns,
            collector,
            start,
            size,
        )
    except QUEUE_FILESYSTEM_EXCEPTIONS as exc:
        record_suppressed_failure(
            "raw_stage_cache_file_probe_failed",
            exc,
            domain="scheduler",
            context={"path": path},
            fatal=True,
        )
        return RAW_STAGE_CACHE_UNAVAILABLE

