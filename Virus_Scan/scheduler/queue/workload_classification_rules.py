"""Bounded workload classification rules for scheduler queue admission."""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Iterable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_tag_texts, scheduler_text
from Virus_Scan.scheduler.queue.workload_path_support import workload_path_extension_context
from Virus_Scan.scheduler.queue.workload_identity import (
    _sniff_workload_identity as _queue_sniff_workload_identity,
    workload_from_identity_outcome as _queue_workload_identity_outcome,
)

WORKLOAD_EXTENSION_ITEMS: tuple[tuple[str, frozenset[str]], ...] = (
    ("archive", frozenset({".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".rpa"})),
    ("dotnet", frozenset({".dll", ".exe"})),
    ("media", frozenset({".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".ogg", ".mp3", ".wav", ".flac", ".mp4", ".webm"})),
    ("script", frozenset({".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".py", ".rpy", ".rpyc"})),
)

_KEYWORD_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("yara", ("yara", "rule")),
    ("archive", ("archive", "extract", "unpack", "rpa")),
    ("dotnet", ("ilspy", "dotnet", "dncil")),
    ("raw", ("raw", "decode", "string")),
    ("image", ("image", "media", "png", "stego")),
)


def classify_workload_from_rules(
    path: str | os.PathLike[str] | None = None,
    *,
    stage: str | None = None,
    tags: Iterable[str] | None = None,
    path_extension_context: Callable[[str | os.PathLike[str] | None], tuple[str, str, str]] = workload_path_extension_context,
) -> str:
    stage_text, stage_reason = scheduler_text(
        stage,
        unsupported_reason="workload_stage_text_rejected",
    )
    tag_text = " ".join(scheduler_tag_texts(tags))
    text = " ".join(part for part in (stage_text, tag_text) if part).lower()
    for workload, keywords in _KEYWORD_RULES:
        if any(keyword in text for keyword in keywords):
            return workload

    ext, path_reason, filesystem_path = path_extension_context(path)
    for workload, extensions in WORKLOAD_EXTENSION_ITEMS:
        if ext in extensions:
            return "image" if workload == "media" else workload

    if path_reason == "" and filesystem_path != "":
        sniffed_decision = _queue_workload_identity_outcome(_queue_sniff_workload_identity(filesystem_path))
        if sniffed_decision.accepted:
            return sniffed_decision.workload

    if stage_reason:
        return "generic"
    return "generic"


__all__ = (
    "WORKLOAD_EXTENSION_ITEMS",
    "classify_workload_from_rules",
)
