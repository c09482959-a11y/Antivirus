"""Queue-owned raw reclaim gates for orphan recovery."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path

from Virus_Scan.scheduler.internal.scheduler_config import process_queue_env_float as _process_queue_env_float_value
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.queue.orphan_recovery_gate_failures import record_reclaim_gate_failure


def _job_value(job: object, *keys: str) -> object:
    if type(job) is dict:
        for key in keys:
            value = dict.get(job, key)
            if value is not None:
                return value
    return ""

def _job_type(job: object) -> str:
    text, reason = no_hook_text(_job_value(job, "job_type"), missing_reason="missing_job_type", unsupported_reason="unsafe_job_type_rejected")
    return text if reason == "" and text else "file"
def apply_raw_stage_reclaim_gate(
    *,
    job: dict[str, object],
    queue_dir: object,
    claim_age: float,
    progress_age: float,
    file_timeout: float,
    progress_stall: float,
    heartbeat_fresh: bool,
    pid_alive: bool,
    raw_stage_progress_recent: Callable[..., bool],
    timeout_expired: bool,
    checkpoint_stalled: bool,
    evidence_records: list[Mapping[str, object]] | None = None,
) -> tuple[bool, bool, bool]:
    """Return (continue_claim, timeout_expired, checkpoint_stalled) for raw-stage claims."""
    if _job_type(job) != "raw_stage":
        return False, timeout_expired, checkpoint_stalled
    raw_timeout = _process_queue_env_float_value(
        "UMIGE_RAW_STAGE_TIMEOUT_SEC",
        0.0,
        minimum=0.0,
        record_suppressed=_process_queue_record_suppressed,
    )
    if raw_timeout <= 0:
        raw_timeout = max(900.0, file_timeout * 10.0, progress_stall * 2.0)
    raw_timeout = max(300.0, raw_timeout)
    raw_quiet = _process_queue_env_float_value(
        "UMIGE_RAW_RECOVERY_QUIET_SEC",
        120.0,
        minimum=0.0,
        record_suppressed=_process_queue_record_suppressed,
    )
    raw_quiet = max(15.0, raw_quiet)
    try:
        raw_recent = raw_stage_progress_recent(queue_dir, quiet_sec=raw_quiet) is True
    except (OSError, RuntimeError, TypeError, ValueError) as probe_exc:
        record_reclaim_gate_failure(
            record_suppressed=_process_queue_record_suppressed,
            evidence_records=evidence_records,
            stage="process_queue_raw_stage_reclaim_gate_probe_failed",
            action="evaluate_raw_stage_reclaim_gate",
            source_path=_job_value(job, "file"),
            destination_path=queue_dir,
            error=probe_exc,
            error_source="orphan_recovery_gates.raw_stage_progress_recent",
            job_id=_job_value(job, "id", "job_id", "file"),
            extra={"queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir"), "job_file": scheduler_evidence_path(_job_value(job, "file"), field_name="job_file")},
        )
        return True, timeout_expired, checkpoint_stalled
    if raw_recent:
        return True, timeout_expired, checkpoint_stalled
    if heartbeat_fresh or pid_alive:
        return True, timeout_expired, checkpoint_stalled
    timeout_expired = bool(claim_age >= raw_timeout)
    checkpoint_stalled = bool(progress_age >= raw_quiet and claim_age >= raw_timeout)
    return (not (timeout_expired and checkpoint_stalled)), timeout_expired, checkpoint_stalled


def apply_raw_owner_reclaim_gate(
    *,
    job: dict[str, object],
    queue_dir: object,
    claim_age: float,
    progress_age: float,
    file_timeout: float,
    progress_stall: float,
    file_has_recent_raw_owner_progress: Callable[..., dict[str, object]],
    timeout_expired: bool,
    checkpoint_stalled: bool,
    evidence_records: list[Mapping[str, object]] | None = None,
) -> tuple[bool, bool, bool]:
    """Return (continue_claim, timeout_expired, checkpoint_stalled) for file jobs owning raw chunks."""
    if _job_type(job) == "raw_stage":
        return False, timeout_expired, checkpoint_stalled
    raw_quiet_owner = _process_queue_env_float_value(
        "UMIGE_RAW_RECOVERY_QUIET_SEC",
        120.0,
        minimum=0.0,
        record_suppressed=_process_queue_record_suppressed,
    )
    raw_quiet_owner = max(15.0, raw_quiet_owner)
    try:
        raw_owner = file_has_recent_raw_owner_progress(queue_dir, _job_value(job, "file"), quiet_sec=raw_quiet_owner)
    except (OSError, RuntimeError, TypeError, ValueError) as owner_exc:
        record_reclaim_gate_failure(
            record_suppressed=_process_queue_record_suppressed,
            evidence_records=evidence_records,
            stage="process_queue_raw_owner_reclaim_gate_probe_failed",
            action="evaluate_raw_owner_reclaim_gate",
            source_path=_job_value(job, "file"),
            destination_path=queue_dir,
            error=owner_exc,
            error_source="orphan_recovery_gates.file_has_recent_raw_owner_progress",
            job_id=_job_value(job, "id", "job_id", "file"),
            extra={"queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir"), "job_file": scheduler_evidence_path(_job_value(job, "file"), field_name="job_file")},
        )
        return True, timeout_expired, checkpoint_stalled
    if not isinstance(raw_owner, dict):
        owner_schema_exc = TypeError("raw owner progress must be a mapping, got " + no_hook_type_name(raw_owner))
        record_reclaim_gate_failure(
            record_suppressed=_process_queue_record_suppressed,
            evidence_records=evidence_records,
            stage="process_queue_raw_owner_reclaim_gate_schema_failed",
            action="evaluate_raw_owner_reclaim_gate",
            source_path=_job_value(job, "file"),
            destination_path=queue_dir,
            error=owner_schema_exc,
            error_source="orphan_recovery_gates.file_has_recent_raw_owner_progress_schema",
            job_id=_job_value(job, "id", "job_id", "file"),
            extra={"queue_dir": scheduler_evidence_path(queue_dir, field_name="queue_dir"), "job_file": scheduler_evidence_path(_job_value(job, "file"), field_name="job_file")},
        )
        return True, timeout_expired, checkpoint_stalled
    has_accumulator = dict.get(raw_owner, "has_accumulator") is True
    complete = dict.get(raw_owner, "complete") is True
    if not (has_accumulator and not complete):
        return False, timeout_expired, checkpoint_stalled
    raw_owner_timeout = _process_queue_env_float_value(
        "UMIGE_RAW_OWNER_TIMEOUT_SEC",
        0.0,
        minimum=0.0,
        record_suppressed=_process_queue_record_suppressed,
    )
    if raw_owner_timeout <= 0:
        raw_owner_timeout = max(900.0, file_timeout * 10.0, progress_stall * 2.0)
    raw_owner_timeout = max(300.0, raw_owner_timeout)
    if dict.get(raw_owner, "recent") is True:
        return True, timeout_expired, checkpoint_stalled
    timeout_expired = bool(claim_age >= raw_owner_timeout)
    checkpoint_stalled = bool(progress_age >= raw_quiet_owner and claim_age >= raw_owner_timeout)
    return (not (timeout_expired and checkpoint_stalled)), timeout_expired, checkpoint_stalled


__all__ = ("apply_raw_owner_reclaim_gate", "apply_raw_stage_reclaim_gate")
