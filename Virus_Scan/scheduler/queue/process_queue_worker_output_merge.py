"""Worker-output file ingestion for process-queue result merging."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_evidence_path,
    scheduler_exception_text,
    scheduler_value_snapshot,
)


def merge_process_queue_worker_outputs(
    outputs: Iterable[object],
    *,
    deps: object,
) -> tuple[dict[object, object], bool]:
    merged: dict[object, object] = {}
    had_error = False
    for output in outputs:
        output_text = scheduler_evidence_path(output, field_name="process_queue_output_path")
        if "unsupported_process_queue_output_path" in output_text:
            had_error = True
            deps.record_issue(
                "process_queue_worker_output_path_rejected",
                TypeError("process queue worker output path was rejected"),
                fatal=True,
                extra={"output_value": scheduler_value_snapshot(output, field_name="process_queue_output_path")},
            )
            deps.log_error("process queue worker output path rejected: " + output_text)
            continue
        if not Path(output_text).exists():
            had_error = True
            missing_output_error = FileNotFoundError(
                "expected process queue worker output is missing: " + output_text
            )
            deps.record_issue(
                "process_queue_worker_output_missing",
                missing_output_error,
                fatal=True,
                extra={"output_path": output_text},
            )
            deps.log_error(scheduler_exception_text(missing_output_error))
            continue
        data = deps.read_json_file(output_text, default={})
        if type(data) is dict:
            merged.update(data)
            continue
        had_error = True
        invalid_output_error = TypeError("process queue worker output JSON was not an exact mapping")
        deps.record_issue(
            "process_queue_worker_output_invalid",
            invalid_output_error,
            fatal=True,
            extra={
                "output_path": output_text,
                "output_value": scheduler_value_snapshot(data, field_name="process_queue_worker_output"),
            },
        )
        deps.log_error("process queue worker output JSON invalid/non-dict: " + output_text)
    return merged, had_error


__all__ = ("merge_process_queue_worker_outputs",)
