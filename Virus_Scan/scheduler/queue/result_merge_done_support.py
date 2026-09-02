"""Support helpers for done-job result merge validation."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.scheduler.api.contracts import QueueResultReadError, QueueResultSchemaError
from Virus_Scan.scheduler.internal.exception_projection import scheduler_error_detail
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.queue.result_merge_load import (
    result_listdir_names as _result_listdir_names,
    result_path as _result_path,
    result_text as _result_text,
)
from Virus_Scan.scheduler.queue.result_merge_load_support import result_listdir_sort_key as _result_listdir_sort_key


result_listdir_sort_key = _result_listdir_sort_key


def merged_result_snapshot(
    *,
    merged_results: Mapping[str, object],
    report: Callable[..., object],
) -> dict[str, object] | list[dict[str, object]]:
    """Return an owned merged-result snapshot or a validation marker list."""
    merged_items = no_hook_mapping_items(merged_results)
    if merged_items is None:
        schema_failure = QueueResultSchemaError("merged scheduler results mapping rejected")
        report("queue_done_result_mapping_rejected", schema_failure, fatal=True)
        return [{
            "queue_validation_failed": True,
            "error": scheduler_error_detail(schema_failure, max_length=500),
        }]
    return dict(merged_items)


def done_directory_names(
    *,
    queue_dir: object,
    job_dirs: Callable[..., object],
    safe_listdir: Callable[..., object],
    report: Callable[..., object],
) -> tuple[Path | None, list[object] | list[dict[str, object]]]:
    """Return the done root and sorted done names, or a validation marker list."""
    try:
        _pending, _active, done_dir, _failed = job_dirs(queue_dir)
        done_root = _result_path(done_dir, field_name="queue_done_directory")
        names = sorted(
            _result_listdir_names(
                safe_listdir,
                done_root,
                field_name="done_directory",
            ),
            key=result_listdir_sort_key,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        read_failure = QueueResultReadError(
            "done queue validation failed: "
            + scheduler_error_detail(exc, max_length=500)
        )
        report(
            "queue_done_result_validation_failed",
            read_failure,
            fatal=True,
            extra={"queue_dir_type": no_hook_type_name(queue_dir)},
        )
        return None, [{
            "queue_validation_failed": True,
            "error": scheduler_error_detail(read_failure, max_length=500),
        }]
    return done_root, names


def append_done_validation_failure(
    missing: list[dict[str, object]],
    *,
    path: object | None = None,
    error: BaseException,
    filename_type: str | None = None,
) -> None:
    """Append a standard done-job validation failure marker."""
    marker: dict[str, object] = {
        "queue_validation_failed": True,
        "error": scheduler_error_detail(error, max_length=500),
    }
    if path is not None:
        marker["path"] = path
    if filename_type is not None:
        marker["filename_type"] = filename_type
    missing.append(marker)


def accepted_done_job_name(
    *,
    name_text: str,
    is_job_json_name: Callable[[str], object],
    report: Callable[..., object],
    missing: list[dict[str, object]],
    path: object,
) -> bool:
    """Return whether the done filename is a job file or append predicate failure evidence."""
    is_job, is_job_reason = scheduler_bool(
        is_job_json_name(name_text),
        reason="queue_result_job_name_predicate_rejected",
    )
    if is_job_reason:
        predicate_failure = QueueResultSchemaError(is_job_reason)
        report("queue_done_job_name_predicate_rejected", predicate_failure, fatal=True)
        append_done_validation_failure(missing, path=path, error=predicate_failure)
        return bool(False)
    return bool(is_job)


def done_job_snapshot(
    *,
    path: object,
    read_json: Callable[..., object],
    report: Callable[..., object],
    missing: list[dict[str, object]],
) -> dict[str, object] | None:
    """Read and materialize one done-job mapping or append validation evidence."""
    try:
        job = read_json(path, default=None)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        job_read_failure = QueueResultReadError(
            "done job read failed: "
            + scheduler_error_detail(exc, max_length=500)
        )
        report("done_job_read_failed", job_read_failure, fatal=True, extra={"job": path})
        append_done_validation_failure(missing, path=path, error=job_read_failure)
        return None
    job_items = no_hook_mapping_items(job)
    if job_items is None:
        job_schema_failure = QueueResultSchemaError("done job is not an exact owned mapping")
        report("done_job_schema_failed", job_schema_failure, fatal=True, extra={"job": path})
        append_done_validation_failure(missing, path=path, error=job_schema_failure)
        return None
    return dict(job_items)


def done_job_type(job_snapshot: Mapping[str, object]) -> str:
    """Project a done-job type field through the queue text contract."""
    job_type_value = dict.get(dict(job_snapshot), "type")
    if job_type_value is None:
        job_type_value = dict.get(dict(job_snapshot), "job_type")
    if job_type_value is None:
        return ""
    return _result_text(job_type_value, field_name="job_type")


def done_job_file_identity(job_snapshot: Mapping[str, object]) -> str | None:
    """Return the first accepted done-job file identity, when present."""
    snapshot = dict(job_snapshot)
    file_value = None
    for key in ("file", "path", "target"):
        candidate = dict.get(snapshot, key)
        if candidate is not None:
            file_value = candidate
            break
    if file_value is None:
        return None
    return _result_text(file_value, field_name="done_file")


__all__ = (
    "accepted_done_job_name",
    "append_done_validation_failure",
    "done_directory_names",
    "done_job_file_identity",
    "done_job_snapshot",
    "done_job_type",
    "merged_result_snapshot",
    "result_listdir_sort_key",
)
