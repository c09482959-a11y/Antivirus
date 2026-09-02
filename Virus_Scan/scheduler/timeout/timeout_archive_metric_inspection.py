"""Archive metric inspection support for timeout workload budgeting."""
from __future__ import annotations

from collections.abc import Iterable
import tarfile
from typing import TYPE_CHECKING
import zipfile

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.timeout.timeout_budget_workload import extension

if TYPE_CHECKING:
    import os

_ARCHIVE_EXTENSIONS = frozenset({
    ".zip",
    ".jar",
    ".whl",
    ".rpa",
    ".tar",
    ".tgz",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
})
_SUPPORTED_ARCHIVE_EXTENSIONS = frozenset({
    ".zip",
    ".jar",
    ".whl",
    ".rpa",
    ".tar",
    ".tgz",
    ".gz",
    ".bz2",
    ".xz",
})


def archive_metrics_unavailable(
    *,
    nested_archive_count: int | None,
    inspection_error: str | None = None,
) -> dict[str, object]:
    metrics: dict[str, object] = {
        "estimated_uncompressed_size": None,
        "archive_member_count": None,
        "largest_member_size": None,
        "compression_ratio": None,
        "nested_archive_count": nested_archive_count,
    }
    if inspection_error is not None:
        metrics["inspection_error"] = inspection_error
    return metrics


def _archive_metrics_from_members(
    members: Iterable[tuple[str | os.PathLike[str] | None, object]],
    file_size: int,
    *,
    size_rejection_reason: str,
) -> dict[str, object]:
    member_count = 0
    uncompressed = 0
    largest = 0
    nested = 0
    for member_name, raw_size in members:
        member_count += 1
        size, _size_reason = scheduler_int(
            raw_size,
            default=0,
            minimum=0,
            reason=size_rejection_reason,
        )
        uncompressed += size
        largest = max(largest, size)
        if extension(member_name) in _ARCHIVE_EXTENSIONS:
            nested += 1
    ratio = float(uncompressed) / float(max(1, file_size))
    return {
        "estimated_uncompressed_size": int(uncompressed),
        "archive_member_count": int(member_count),
        "largest_member_size": int(largest),
        "compression_ratio": round(ratio, 6),
        "nested_archive_count": int(nested),
    }


def _zip_archive_metrics(
    path: str | os.PathLike[str],
    file_size: int,
) -> dict[str, object]:
    with zipfile.ZipFile(path) as zf:
        return _archive_metrics_from_members(
            ((info.filename, info.file_size) for info in zf.infolist()),
            file_size,
            size_rejection_reason="zip_member_size_rejected",
        )


def _tar_archive_metrics(
    path: str | os.PathLike[str],
    file_size: int,
) -> dict[str, object]:
    with tarfile.open(path) as tf:
        return _archive_metrics_from_members(
            ((member.name, member.size) for member in tf),
            file_size,
            size_rejection_reason="tar_member_size_rejected",
        )


def archive_metrics_for_path(
    path: str | os.PathLike[str],
    file_size: int,
) -> dict[str, object]:
    ext = extension(path)
    if ext in _ARCHIVE_EXTENSIONS and ext not in _SUPPORTED_ARCHIVE_EXTENSIONS:
        return archive_metrics_unavailable(
            nested_archive_count=0,
            inspection_error="unsupported_archive_format:%s" % (ext or "<none>"),
        )
    if ext in {".zip", ".jar", ".whl", ".rpa"}:
        return _zip_archive_metrics(path, file_size)
    if ext in {".tar", ".tgz", ".gz", ".bz2", ".xz"}:
        return _tar_archive_metrics(path, file_size)
    return archive_metrics_unavailable(nested_archive_count=0)


__all__ = ("archive_metrics_for_path", "archive_metrics_unavailable")
