"""Workload classification helpers for timeout budget ownership."""
from __future__ import annotations

import os

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_error_detail,
    scheduler_filesystem_path,
    scheduler_join_texts,
    scheduler_tag_texts,
)
from Virus_Scan.scheduler.timeout.timeout_budget_workload_decisions import (
    configured_timeout_error_decision,
    workload_extension_decision,
    workload_size_megabytes_decision,
)

_ARCHIVE_EXTENSIONS = frozenset({".zip", ".jar", ".whl", ".rpa", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"})
_DOTNET_EXTENSIONS = frozenset({".dll", ".exe"})
_IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"})
_MEDIA_EXTENSIONS = frozenset({".ogg", ".mp3", ".wav", ".flac", ".mp4", ".webm"})
_SCRIPT_EXTENSIONS = frozenset({".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".py", ".rpy", ".rpyc"})


def safe_file_size_with_error(path: str | os.PathLike[str] | None, *, getsize: object=None) -> tuple[int, str | None]:
    if getsize is not None and getsize is not os.path.getsize:
        return 0, "scheduler_file_size_probe_rejected"
    size_probe = os.path.getsize
    safe_path, path_reason = scheduler_filesystem_path(path)
    if path_reason:
        return 0, "scheduler_path_rejected: " + str.__str__(path_reason)
    try:
        size = size_probe(safe_path)
        decision = workload_size_megabytes_decision(size)
        if not decision.accepted:
            return 0, "scheduler_file_size_rejected: " + decision.reason
        return int(decision.size_bytes), None
    except (OSError, TypeError, ValueError) as exc:
        return 0, scheduler_error_detail(exc, max_length=160)


def configured_timeout_error(configured_timeout_seconds: float | str | None) -> str | None:
    return configured_timeout_error_decision(configured_timeout_seconds).error


def mb(size_bytes: float | None) -> float:
    return workload_size_megabytes_decision(size_bytes).megabytes


def extension(path: str | os.PathLike[str] | None) -> str:
    return workload_extension_decision(path).extension


def infer_workload(path: str | os.PathLike[str] | None, workload_class: str | None, method: str | None, tags: object) -> str:
    text = scheduler_join_texts(workload_class, method, *scheduler_tag_texts(tags)).lower()
    ext = extension(path)
    if "archive" in text or ext in _ARCHIVE_EXTENSIONS:
        return "archive"
    if "ilspy" in text or "dotnet" in text or ext in _DOTNET_EXTENSIONS:
        return "dotnet_decompile"
    if "yara" in text:
        return "yara_scan"
    if "stego" in text or "deep_image" in text:
        return "deep_image_scan"
    if "deep" in text:
        return "deep_scan"
    if ext in _IMAGE_EXTENSIONS:
        return "image_fast_triage"
    if ext in _MEDIA_EXTENSIONS:
        return "media_scan"
    if ext in _SCRIPT_EXTENSIONS:
        return "script_scan"
    return "generic_scan"


__all__ = (
    "configured_timeout_error",
    "configured_timeout_error_decision",
    "extension",
    "infer_workload",
    "mb",
    "safe_file_size_with_error",
    "workload_extension_decision",
    "workload_size_megabytes_decision",
)
