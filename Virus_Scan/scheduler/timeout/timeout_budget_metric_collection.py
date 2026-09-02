"""Timeout-budget metric materialization helpers."""
from __future__ import annotations

import tarfile
import zipfile

from Virus_Scan.contracts.artifact_read_snapshot import require_artifact_read_snapshot

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_error_detail,
    scheduler_float,
    scheduler_int,
    scheduler_text,
)
from Virus_Scan.scheduler.timeout.timeout_budget_workload import safe_file_size_with_error
from Virus_Scan.scheduler.timeout.timeout_workload_inspection import (
    archive_metrics,
    image_pixel_count,
)


def join_timeout_inspection_error(*parts: str | None) -> str | None:
    """Join non-empty timeout inspection evidence messages."""
    joined = "; ".join(part for part in parts if part)
    return joined or None


def timeout_file_size(path: object, file_size_probe: object, artifact_read_snapshot: object = None) -> tuple[int, str | None]:
    """Return the source file size or an explicit probe-rejection reason."""
    if artifact_read_snapshot is not None:
        if file_size_probe is not None:
            return 0, "scheduler_file_size_probe_conflicts_with_artifact_snapshot"
        try:
            snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
        except (OSError, RuntimeError, TypeError, UnicodeError, ValueError) as exc:
            return 0, scheduler_error_detail(exc, max_length=160)
        if not snapshot.complete:
            return 0, "artifact_read_snapshot_" + snapshot.state + ":" + snapshot.unavailable_reason
        return snapshot.size, None
    if file_size_probe is None:
        return safe_file_size_with_error(path)
    return 0, "scheduler_file_size_probe_rejected"


def _archive_metrics_with_error(path: object, file_size: int) -> tuple[dict[str, object], str | None]:
    """Read archive metrics, preserving bounded inspection failure evidence."""
    try:
        metrics = archive_metrics(path, file_size)
    except (OSError, RuntimeError, TypeError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        return (
            {
                "estimated_uncompressed_size": None,
                "archive_member_count": None,
                "largest_member_size": None,
                "compression_ratio": None,
                "nested_archive_count": 0,
            },
            scheduler_error_detail(exc, max_length=160),
        )
    metrics_error = scheduler_mapping_value(metrics, "inspection_error")
    metrics_error_text, metrics_error_reason = scheduler_text(
        metrics_error,
        replacement_text="",
        unsupported_reason="timeout_metrics_error_rejected",
    )
    if metrics_error_reason == "" and metrics_error_text:
        return metrics, metrics_error_text
    return metrics, None


def timeout_inspection_metrics(
    *,
    path: object,
    workload: str,
    file_size: int,
    inspection_error: str | None,
    artifact_read_snapshot: object = None,
) -> tuple[dict[str, object], int | None, str | None]:
    """Return workload-specific inspection metrics and cumulative evidence."""
    metrics: dict[str, object] = {}
    image_pixels = None
    if workload in {"image_fast_triage", "deep_image_scan"}:
        image_pixels, image_error = image_pixel_count(path, artifact_read_snapshot=artifact_read_snapshot)
        inspection_error = join_timeout_inspection_error(inspection_error, image_error)
    if workload == "archive":
        metrics, archive_error = _archive_metrics_with_error(path, file_size)
        inspection_error = join_timeout_inspection_error(inspection_error, archive_error)
    return metrics, image_pixels, inspection_error


def optional_int_timeout_metric(value: object) -> int | None:
    """Return an optional non-negative integer metric without hooks."""
    if value is None:
        return None
    parsed, reason = scheduler_int(
        value,
        default=0,
        minimum=0,
        reason="timeout_metric_int_rejected",
    )
    return None if reason else parsed


def optional_float_timeout_metric(value: object) -> float | None:
    """Return an optional non-negative float metric without hooks."""
    if value is None:
        return None
    parsed, reason = scheduler_float(
        value,
        default=0.0,
        minimum=0.0,
        reason="timeout_metric_float_rejected",
    )
    return None if reason else parsed


def timeout_method_name(method: object, workload: str) -> str:
    """Materialize the timeout method evidence name."""
    method_name, method_reason = scheduler_text(
        method,
        replacement_text=workload,
        unsupported_reason="timeout_method_rejected",
    )
    if method_reason != "" or not method_name:
        return workload
    return method_name
