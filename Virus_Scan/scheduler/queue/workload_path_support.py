"""Canonical no-hook path-extension materialization for workload classification."""
from __future__ import annotations

import os

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_filesystem_path,
    scheduler_path_text,
)


def workload_path_extension_context(
    path: str | os.PathLike[str] | None,
) -> tuple[str, str, str]:
    filesystem_path, path_reason = scheduler_filesystem_path(path)
    if path_reason != "" or filesystem_path == "":
        return "", path_reason, filesystem_path
    path_text, text_reason = scheduler_path_text(filesystem_path)
    if text_reason != "":
        return "", path_reason, filesystem_path
    return os.path.splitext(path_text)[1].lower(), path_reason, filesystem_path
