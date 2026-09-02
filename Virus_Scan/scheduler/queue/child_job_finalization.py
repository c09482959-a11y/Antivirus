"""Queue-owned child-job finalization helpers.

Worker lifecycle modules receive these operations as explicit callbacks.  The
queue domain owns claim finalization and raw-stage accumulator mutation.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.scheduler.queue.process_queue_finalization import _finish_process_queue_job
from Virus_Scan.scheduler.queue.raw_accumulator_store import RawAccumulatorStore

if TYPE_CHECKING:
    from collections.abc import Mapping


def finish_child_process_queue_job(work_queue_dir: object, claim_path: object, *, ok: bool, error_info: object, job: Mapping[str, object] | None) -> object:
    """Finalize one claimed child job through the queue-owned claim path."""
    return _finish_process_queue_job(work_queue_dir, claim_path, ok=ok, error_info=error_info, job=job)


def append_child_raw_stage_result(work_queue_dir: object, job: Mapping[str, object], raw_result: Mapping[str, object]) -> None:
    """Append one raw-stage result through queue-owned accumulator storage."""
    RawAccumulatorStore(work_queue_dir, job.get("file_id")).append(raw_result)


__all__ = ("append_child_raw_stage_result", "finish_child_process_queue_job")
