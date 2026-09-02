"""Raw-stage claim repair and validation."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.scheduler.ownership.raw_queue_claim_raw_recovery import (
    build_invalid_raw_claim_failure,
    repair_raw_claim_file_from_accumulator,
)
from Virus_Scan.scheduler.ownership.raw_queue_claim_values import claim_sequence, claim_text


def validate_raw_claim(
    queue_dir: object,
    normalized: dict[str, object],
    *,
    job_type_reason: str,
    failure_info: Callable[..., dict[str, object]],
    file_id_for_path: Callable[[object], str],
    accumulator_factory: Callable[[object, str], object],
    report: Callable[..., object],
    worker_pid: int,
) -> tuple[dict[str, object], dict[str, object] | None]:
    normalized["job_type"] = "raw_stage"
    file_id, file_id_reason = claim_text(dict.get(normalized, "file_id"), field="file_id", report=report)
    if file_id == "":
        raw_file_id, raw_reason = claim_text(dict.get(normalized, "raw_file_id"), field="raw_file_id", report=report)
        if raw_file_id:
            file_id, file_id_reason = raw_file_id, raw_reason
    file_path, file_reason = claim_text(dict.get(normalized, "file"), field="file", report=report)
    if file_id == "" and file_path:
        try:
            file_id, file_id_reason = claim_text(
                file_id_for_path(file_path),
                field="derived_file_id",
                report=report,
            )
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            report("queue_claim_raw_file_id_repair_failed", exc, fatal=True, extra={"file": file_path[:500]})
    if file_id:
        normalized["file_id"] = file_id
    if file_path:
        normalized["file"] = file_path
    collector, collector_reason = claim_text(dict.get(normalized, "collector"), field="collector", report=report)
    if collector:
        normalized["collector"] = collector
    seq, seq_reason = claim_sequence(dict.get(normalized, "seq"), field="seq", report=report)
    if seq is not None:
        normalized["seq"] = seq
    missing = []
    if file_id == "" or file_id_reason:
        missing.append("file_id")
    if collector == "" or collector_reason:
        missing.append("collector")
    if seq is None or seq_reason:
        missing.append("seq")
    file_path = repair_raw_claim_file_from_accumulator(
        normalized=normalized,
        queue_dir=queue_dir,
        file_id=file_id,
        file_path=file_path,
        accumulator_factory=accumulator_factory,
        report=report,
    )
    if file_path == "":
        missing.append("file")
    if not missing:
        return normalized, None
    return normalized, build_invalid_raw_claim_failure(
        normalized=normalized,
        failure_info=failure_info,
        worker_pid=worker_pid,
        missing=missing,
        job_type_reason=job_type_reason,
        file_id=file_id,
        file_id_reason=file_id_reason,
        collector=collector,
        collector_reason=collector_reason,
        seq=seq,
        seq_reason=seq_reason,
        file_reason=file_reason,
    )


__all__ = ("validate_raw_claim",)
