"""Static timeout workload inspection helpers.

This module owns header-only image/archive inspection used to compute immutable
timeout budgets without runtime dependency discovery or expensive decoding.
"""
from __future__ import annotations

import struct

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_error_detail,
    scheduler_filesystem_path,
    scheduler_int,
)
from Virus_Scan.scheduler.timeout.timeout_archive_metric_inspection import (
    archive_metrics_for_path,
    archive_metrics_unavailable,
)
from Virus_Scan.scheduler.timeout.timeout_budget_workload import extension
from Virus_Scan.scheduler.timeout.timeout_image_header_inspection import (
    static_image_pixel_count,
)

if TYPE_CHECKING:
    import os

_IMAGE_EXTENSIONS = frozenset({
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
    ".gif",
})


def image_pixel_count(
    path: str | os.PathLike[str] | None,
    *,
    artifact_read_snapshot: object = None,
) -> tuple[int | None, str | None]:
    """Return bounded image pixel count using static header parsing only.

    Timeout budgeting must not import optional image libraries or decode full
    images.  This owner reads only small fixed headers so the budget model can
    scale deep-image work by dimensions without adding runtime dependency
    discovery or expensive pre-scan decoding.
    """
    safe_path, path_reason = scheduler_filesystem_path(path)
    if path_reason or (type(safe_path) is str and safe_path == ""):
        return None, ("image_path_unavailable:" + str.__str__(path_reason)) if path_reason else "image_path_unavailable:scheduler_path_missing"
    try:
        if artifact_read_snapshot is not None:
            snapshot = require_artifact_read_snapshot(artifact_read_snapshot, safe_path)
            if not snapshot.complete:
                return None, "artifact_read_snapshot_" + snapshot.state + ":" + snapshot.unavailable_reason
            head = snapshot.read_prefix(65536)
        else:
            with open(safe_path, "rb") as fh:
                head = fh.read(65536)
        pixels, error = static_image_pixel_count(head)
        if pixels is not None or error is not None:
            return pixels, error
    except (OSError, RuntimeError, TypeError, ValueError, struct.error) as exc:
        return None, scheduler_error_detail(exc, max_length=120)
    ext = extension(safe_path)
    if ext in _IMAGE_EXTENSIONS:
        return None, "unrecognized_image_header:%s" % (ext or "<none>")
    return None, None


def archive_metrics(
    path: str | os.PathLike[str] | None,
    file_size: int,
) -> dict[str, object]:
    safe_path, path_reason = scheduler_filesystem_path(path)
    if path_reason or (type(safe_path) is str and safe_path == ""):
        return archive_metrics_unavailable(
            nested_archive_count=None,
            inspection_error=("archive_path_unavailable:" + str.__str__(path_reason)) if path_reason else "archive_path_unavailable:scheduler_path_missing",
        )
    safe_size, size_reason = scheduler_int(
        file_size,
        default=0,
        minimum=0,
        reason="archive_file_size_rejected",
    )
    if size_reason:
        return archive_metrics_unavailable(
            nested_archive_count=None,
            inspection_error=size_reason,
        )
    return archive_metrics_for_path(safe_path, safe_size)


__all__ = (
    "archive_metrics",
    "image_pixel_count",
)
