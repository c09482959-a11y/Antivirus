"""Queue-owned durable result merge and done-job validation.

This module is the canonical queue-domain owner for process/raw queue result
readback. It fails closed for corrupt result records and returns explicit
validation markers for done-job accounting failures so finalization can record
degraded scheduler evidence instead of silently producing clean output.
"""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.api.contracts import QueueResultMissingError, QueueResultSchemaError
from Virus_Scan.scheduler.queue.result_merge_done_support import (
    accepted_done_job_name,
    append_done_validation_failure,
    done_directory_names,
    done_job_file_identity,
    done_job_snapshot,
    done_job_type,
    merged_result_snapshot,
)
from Virus_Scan.scheduler.queue.result_merge_load import (
    load_queue_file_results,
    result_text as _result_text,
)


def done_jobs_missing_results(
    queue_dir: object,
    merged_results: Mapping[str, object],
    *,
    job_dirs: object,
    safe_listdir: object,
    is_job_json_name: object,
    read_json: object,
    report: object,
) -> list[dict[str, object]]:
    """Return done file jobs without durable merged results or validation markers."""
    missing: list[dict[str, object]] = []
    merged_snapshot_or_marker = merged_result_snapshot(
        merged_results=merged_results,
        report=report,
    )
    if isinstance(merged_snapshot_or_marker, list):
        return merged_snapshot_or_marker
    merged_snapshot = merged_snapshot_or_marker
    done_root, names_or_marker = done_directory_names(
        queue_dir=queue_dir,
        job_dirs=job_dirs,
        safe_listdir=safe_listdir,
        report=report,
    )
    if done_root is None:
        return names_or_marker
    for name in names_or_marker:
        try:
            name_text = _result_text(name, field_name="done_filename")
        except QueueResultSchemaError as exc:
            report("queue_done_filename_rejected", exc, fatal=True)
            append_done_validation_failure(
                missing,
                error=exc,
                filename_type=no_hook_type_name(name),
            )
            continue
        path = done_root / name_text
        if not accepted_done_job_name(
            name_text=name_text,
            is_job_json_name=is_job_json_name,
            report=report,
            missing=missing,
            path=path,
        ):
            continue
        job_snapshot = done_job_snapshot(
            path=path,
            read_json=read_json,
            report=report,
            missing=missing,
        )
        if job_snapshot is None or done_job_type(job_snapshot) == "raw":
            continue
        file_path = done_job_file_identity(job_snapshot)
        if file_path is None:
            missing_failure = QueueResultMissingError("done job missing file identity")
            report("done_job_file_identity_missing", missing_failure, fatal=True, extra={"job": path})
            append_done_validation_failure(missing, path=path, error=missing_failure)
        elif file_path not in merged_snapshot:
            missing.append({"path": path, "job": job_snapshot, "file": file_path})
    return missing


__all__ = ("done_jobs_missing_results", "load_queue_file_results")
