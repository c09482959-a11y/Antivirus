"""Immutable timeout/escalation evidence for in-memory worker memory toxicity."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, MutableMapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_evidence_text,
    scheduler_exception_text,
    scheduler_float,
    scheduler_int,
)



@dataclass(frozen=True, slots=True)
class InMemoryMemoryToxicityEvidence:
    """Replay-visible evidence for memory-toxicity timeout/escalation decisions."""

    pid: int
    job_id: int | None
    reason: str
    action: str
    error_category: str
    error_source: str
    detail: str
    rss_mb: float = 0.0
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True

    def as_record(self) -> Mapping[str, object]:
        safe_pid, _pid_reason = scheduler_int(self.pid, default=0, reason="unsafe_memory_toxicity_pid")
        safe_job_id, _job_id_reason = scheduler_int(self.job_id, default=0, reason="unsafe_memory_toxicity_job_id")
        safe_rss, _rss_reason = scheduler_float(
            self.rss_mb,
            default=0.0,
            minimum=0.0,
            reason="unsafe_memory_toxicity_rss",
        )
        safe_detail = scheduler_evidence_text(
            self.detail,
            missing_text="memory_toxicity_detail_unavailable",
            field_name="memory_toxicity_detail",
        )
        record: dict[str, object] = {
            "stage": "inmemory_worker_memory_toxicity_escalation",
            "pid": safe_pid,
            "job_id": None if self.job_id is None else safe_job_id,
            "reason": scheduler_evidence_text(
                self.reason,
                missing_text="worker_memory_toxic",
                field_name="memory_toxicity_reason",
            ),
            "action": scheduler_evidence_text(
                self.action,
                missing_text="memory_toxicity_escalation",
                field_name="memory_toxicity_action",
            ),
            "rss_mb": safe_rss,
            "error_category": scheduler_evidence_text(
                self.error_category,
                missing_text="timeout_error",
                field_name="memory_toxicity_error_category",
            ),
            "error_source": scheduler_evidence_text(
                self.error_source,
                missing_text="memory_toxicity",
                field_name="memory_toxicity_source",
            ),
            "detail": safe_detail[:1000],
            "final_json_must_record": scheduler_bool(self.final_json_must_record, default=True, reason="memory_toxicity_flag_rejected")[0],
            "checkpoint_must_record": scheduler_bool(self.checkpoint_must_record, default=True, reason="memory_toxicity_flag_rejected")[0],
            "replay_must_reproduce": scheduler_bool(self.replay_must_reproduce, default=True, reason="memory_toxicity_flag_rejected")[0],
        }
        return MappingProxyType(record)

    def as_scan_integrity(self) -> dict[str, object]:
        record = self.as_record()
        return {
            "timeout_failure": True,
            "retry_failure": True,
            "had_degraded_stage": True,
            "memory_toxicity_escalation_failed": True,
            "memory_toxicity_pid": record["pid"],
            "memory_toxicity_job_id": record["job_id"],
            "memory_toxicity_reason": record["reason"],
            "memory_toxicity_action": record["action"],
            "memory_toxicity_error_category": record["error_category"],
            "memory_toxicity_error_source": record["error_source"],
            "memory_toxicity_detail": record["detail"],
            "allow_learning": False,
        }


def memory_toxicity_evidence(
    *,
    pid: object,
    job_id: object,
    reason: str,
    action: str,
    rss_mb: object,
    error: BaseException,
    source: str,
) -> InMemoryMemoryToxicityEvidence:
    safe_pid, pid_reason = scheduler_int(pid, default=0, reason="unsafe_memory_toxicity_pid")
    safe_job_id, job_id_reason = scheduler_int(
        job_id,
        default=0,
        reason="unsafe_memory_toxicity_job_id",
    )
    safe_rss, rss_reason = scheduler_float(
        rss_mb,
        default=0.0,
        minimum=0.0,
        reason="unsafe_memory_toxicity_rss",
    )
    detail = scheduler_exception_text(error)
    rejected = tuple(reason for reason in (pid_reason, job_id_reason, rss_reason) if reason)
    if rejected:
        detail = detail + "; input_rejections=" + ",".join(rejected)
    return InMemoryMemoryToxicityEvidence(
        pid=safe_pid,
        job_id=None if job_id is None else safe_job_id,
        reason=scheduler_evidence_text(
            reason,
            missing_text="worker_memory_toxic",
            field_name="memory_toxicity_reason",
        ),
        action=scheduler_evidence_text(
            action,
            missing_text="memory_toxicity_escalation",
            field_name="memory_toxicity_action",
        ),
        rss_mb=safe_rss,
        error_category=no_hook_type_name(error),
        error_source=scheduler_evidence_text(
            source,
            missing_text="memory_toxicity",
            field_name="memory_toxicity_source",
        ),
        detail=detail,
    )


def attach_memory_toxicity_evidence(
    *,
    evidence: InMemoryMemoryToxicityEvidence,
    active_info: MutableMapping[str, object] | None,
    job_record: MutableMapping[str, object] | None,
    worker_metrics: MutableMapping[object, object] | None,
) -> None:
    record = dict(evidence.as_record())
    scan_integrity = evidence.as_scan_integrity()
    if active_info is not None:
        current = tuple(active_info.get("memory_toxicity_evidence") or ())
        active_info["memory_toxicity_evidence"] = (*current, record)
        active_info["memory_toxicity_failed"] = True
    if job_record is not None:
        current_records = tuple(job_record.get("timeout_retry_evidence") or ())
        job_record["timeout_retry_evidence"] = (*current_records, record)
        integrity = dict(job_record.get("scan_integrity") or {})
        integrity.update(scan_integrity)
        job_record["scan_integrity"] = integrity
    if worker_metrics is not None:
        metrics = worker_metrics.get(evidence.pid)
        if isinstance(metrics, MutableMapping):
            current = tuple(metrics.get("memory_toxicity_evidence") or ())
            metrics["memory_toxicity_evidence"] = (*current, record)
            metrics["memory_toxicity_failed"] = True


__all__ = (
    "InMemoryMemoryToxicityEvidence",
    "attach_memory_toxicity_evidence",
    "memory_toxicity_evidence",
)
