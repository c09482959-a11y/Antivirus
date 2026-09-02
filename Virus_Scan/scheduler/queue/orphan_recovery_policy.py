"""Queue-owned stale-claim reclaim policy construction."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.queue.orphan_recovery_timeout_evidence import resolve_reclaim_float_value, resolve_reclaim_int_value
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.internal.scheduler_config import (
    process_queue_env_float as _process_queue_env_float_value,
    process_queue_env_int as _process_queue_env_int_value,
)


@dataclass(frozen=True)
class QueueReclaimPolicy:
    stale: float
    retries: int
    progress_stall: float
    file_timeout: float
    evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", immutable_tuple(self.evidence))


def load_queue_reclaim_policy(
    *,
    stale_sec: object = None,
    max_retries: object = None,
    progress_stall_sec: object = None,
    per_file_timeout_sec: object = None,
) -> QueueReclaimPolicy:
    """Resolve retry/stall/timeout policy without mutating queue execution state."""
    evidence: list[Mapping[str, object]] = []
    if stale_sec is None:
        stale = _process_queue_env_float_value("UMIGE_QUEUE_ORPHAN_STALE_SEC", 300.0, minimum=60.0, record_suppressed=_process_queue_record_suppressed)
    else:
        stale_value = resolve_reclaim_float_value(value=stale_sec, field="queue_reclaim_stale_sec", default_value=300.0, evidence=evidence)
        stale = max(stale_value, 60.0)
    retries = (
        _process_queue_env_int_value("UMIGE_QUEUE_ORPHAN_MAX_RETRIES", 1, minimum=0, record_suppressed=_process_queue_record_suppressed)
        if max_retries is None
        else resolve_reclaim_int_value(value=max_retries, field="queue_reclaim_max_retries", default_value=0, evidence=evidence)
    )
    progress_stall = (
        _process_queue_env_float_value("UMIGE_QUEUE_PROGRESS_STALL_SEC", 0.0, minimum=0.0, record_suppressed=_process_queue_record_suppressed)
        if progress_stall_sec is None
        else resolve_reclaim_float_value(value=progress_stall_sec, field="queue_reclaim_progress_stall_sec", default_value=0.0, evidence=evidence)
    )
    if progress_stall <= 0:
        pft = _process_queue_env_float_value("UMIGE_PER_FILE_TIMEOUT_SEC", 0.0, minimum=0.0, record_suppressed=_process_queue_record_suppressed)
        progress_stall = max(stale, pft * 2.0 if pft > 0 else 0.0, 300.0)
    progress_stall = max(60.0, progress_stall)
    file_timeout = (
        _process_queue_env_float_value("UMIGE_PER_FILE_TIMEOUT_SEC", 0.0, minimum=0.0, record_suppressed=_process_queue_record_suppressed)
        if per_file_timeout_sec is None
        else resolve_reclaim_float_value(value=per_file_timeout_sec, field="queue_reclaim_per_file_timeout_sec", default_value=0.0, evidence=evidence)
    )
    if file_timeout <= 0:
        file_timeout = 300.0
    file_timeout = max(30.0, file_timeout)
    return QueueReclaimPolicy(stale=stale, retries=retries, progress_stall=progress_stall, file_timeout=file_timeout, evidence=tuple(evidence))


__all__ = ("QueueReclaimPolicy", "load_queue_reclaim_policy")
