"""Durable per-file queue result loading and schema validation."""
from __future__ import annotations

from Virus_Scan.scheduler.queue.result_merge_load_steps import (
    listed_queue_result_names,
    merge_one_queue_file_result,
)
from Virus_Scan.scheduler.queue.result_merge_load_support import (
    result_listdir_names,
    result_path,
    result_text,
)


def load_queue_file_results(
    queue_dir: object,
    *,
    file_results_dir: object,
    safe_listdir: object,
    read_json: object,
    report: object,
) -> dict[str, object]:
    """Load durable per-file queue results with queue-owned validation."""

    merged: dict[str, object] = {}
    result_root = result_path(
        file_results_dir(queue_dir),
        field_name="queue_result_directory",
    )
    for name in listed_queue_result_names(
        result_root=result_root,
        safe_listdir=safe_listdir,
        report=report,
    ):
        merge_one_queue_file_result(
            merged=merged,
            result_root=result_root,
            name=name,
            read_json=read_json,
            report=report,
        )
    return merged


__all__ = (
    "load_queue_file_results",
    "result_listdir_names",
    "result_path",
    "result_text",
)
