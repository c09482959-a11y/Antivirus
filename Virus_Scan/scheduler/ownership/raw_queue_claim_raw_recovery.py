"""Accumulator recovery and invalid-claim failure evidence for raw-stage claims."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_materialize
from Virus_Scan.scheduler.ownership.raw_queue_claim_values import claim_text


def repair_raw_claim_file_from_accumulator(
    *,
    normalized: dict[str, object],
    queue_dir: object,
    file_id: str,
    file_path: str,
    accumulator_factory: Callable[[object, str], object],
    report: Callable[..., object],
) -> str:
    if file_path != "" or not file_id:
        return file_path
    try:
        accum = accumulator_factory(queue_dir, file_id).load()
        accum_items = no_hook_mapping_items(accum)
        accum_mapping = dict(accum_items) if accum_items is not None else None
        recovered_file, recovered_reason = claim_text(
            dict.get(accum_mapping, "file") if accum_mapping is not None else None,
            field="accumulator_file",
            report=report,
        )
        if not recovered_file or recovered_reason:
            return file_path
        normalized["file"] = recovered_file
        queue_info = dict.get(normalized, "queue_info")
        queue_items = no_hook_mapping_items(queue_info)
        qi = dict(queue_items) if queue_items is not None else {}
        if queue_info is not None and queue_items is None:
            qi["queue_info_unavailable"] = no_hook_materialize(
                queue_info,
                reason_prefix="queue_claim_queue_info",
            )
        marker, marker_reason = claim_text(
            dict.get(qi, "progress_marker"),
            field="progress_marker",
            report=report,
        )
        qi["repaired_file_from_accumulator"] = True
        qi["progress_marker"] = marker if marker and not marker_reason else "claim_repaired_raw_file"
        normalized["queue_info"] = qi
        return recovered_file
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        report(
            "queue_claim_accumulator_file_repair_failed",
            exc,
            fatal=True,
            extra={"file_id": file_id[:200]},
        )
        return file_path


def build_invalid_raw_claim_failure(
    *,
    normalized: dict[str, object],
    failure_info: Callable[..., dict[str, object]],
    worker_pid: int,
    missing: list[str],
    job_type_reason: str,
    file_id: str,
    file_id_reason: str,
    collector: str,
    collector_reason: str,
    seq: object,
    seq_reason: str,
    file_reason: str,
) -> dict[str, object]:
    failure = failure_info(
        stage="queue_claim_invalid_raw_stage_job",
        exception_type="InvalidRawStageQueueJob",
        error="raw-stage queue job missing required field(s): " + ",".join(missing),
        worker_pid=worker_pid,
        attempt=no_hook_materialize(dict.get(normalized, "attempt"), reason_prefix="queue_claim_attempt"),
        extra={
            "job_type": "raw_stage",
            "file_id": file_id or None,
            "collector": collector or None,
            "seq": seq,
            "field_rejections": tuple(
                reason
                for reason in (job_type_reason, file_id_reason, collector_reason, seq_reason, file_reason)
                if reason
            ),
        },
    )
    return failure
