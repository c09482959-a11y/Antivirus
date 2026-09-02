"""Queue-owned active-claim state loading for orphan recovery."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, TYPE_CHECKING

from Virus_Scan.scheduler.evidence.process_queue_errors import (
    process_queue_record_suppressed as _process_queue_record_suppressed,
    record_scheduler_suppressed,
)
from Virus_Scan.scheduler.internal.immutable_outputs import (
    immutable_mapping,
    immutable_tuple,
    materialize_scheduler_mapping,
)
from Virus_Scan.scheduler.internal.scheduler_config import process_queue_env_float as _process_queue_env_float_value
from Virus_Scan.scheduler.queue.authority import queue_path_mtime_age as _process_queue_path_mtime_age
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state_steps import (
    _claim_numeric as _claim_numeric_step,
    active_claim_ages,
    active_claim_liveness,
    active_claim_metric_times,
    load_claim_payload_or_defer,
    merge_active_claim_job,
    mtime_source_age,
    queue_info_or_defer,
)

if TYPE_CHECKING:
    from pathlib import Path


def _claim_numeric(
    value: object,
    *,
    field: str,
    default: float,
) -> tuple[float, Mapping[str, object] | None]:
    return _claim_numeric_step(value, field=field, default=default)


@dataclass(frozen=True)
class ActiveClaimState:
    job: dict[str, object]
    queue_info: dict[str, object]
    hb_age: float
    claim_age: float
    progress_age: float
    pid: object
    pid_alive: bool
    heartbeat_fresh: bool
    timeout_expired: bool
    checkpoint_stalled: bool
    recovery_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        # Preserve queue-internal mutable action semantics while severing caller-owned dictionaries.
        object.__setattr__(self, "job", materialize_scheduler_mapping(immutable_mapping(self.job or {})))
        object.__setattr__(self, "queue_info", materialize_scheduler_mapping(immutable_mapping(self.queue_info or {})))
        object.__setattr__(self, "recovery_evidence", immutable_tuple(self.recovery_evidence))

    def as_snapshot(self) -> Mapping[str, object]:
        return immutable_mapping({
            "job": self.job,
            "queue_info": self.queue_info,
            "hb_age": self.hb_age,
            "claim_age": self.claim_age,
            "progress_age": self.progress_age,
            "pid": self.pid,
            "pid_alive": self.pid_alive,
            "heartbeat_fresh": self.heartbeat_fresh,
            "timeout_expired": self.timeout_expired,
            "checkpoint_stalled": self.checkpoint_stalled,
            "recovery_evidence": self.recovery_evidence,
        })


def load_active_claim_state(
    src: Path,
    *,
    now: float,
    stale: float,
    file_timeout: float,
    progress_stall: float,
    worker_liveness_checker: Callable[..., object],
    deferred_recovery_evidence: list[Mapping[str, object]] | None = None,
) -> ActiveClaimState | None:
    """Load one active claim and return deterministic reclaim state, or None if too new."""
    active_age = _process_queue_path_mtime_age(src, now=now, record_suppressed=record_scheduler_suppressed)
    claim_grace = _process_queue_env_float_value(
        "UMIGE_QUEUE_ACTIVE_CLAIM_GRACE_SEC",
        60.0,
        minimum=15.0,
        record_suppressed=_process_queue_record_suppressed,
    )
    job, recovery_evidence = load_claim_payload_or_defer(
        src,
        active_age=active_age,
        claim_grace=claim_grace,
        deferred_recovery_evidence=deferred_recovery_evidence,
    )
    if job is None or recovery_evidence is None:
        return None
    job = merge_active_claim_job(src, job)
    qi = queue_info_or_defer(
        src,
        job,
        active_age=active_age,
        claim_grace=claim_grace,
        recovery_evidence=recovery_evidence,
        deferred_recovery_evidence=deferred_recovery_evidence,
    )
    if qi is None:
        return None
    claimed, hb, progress_ts = active_claim_metric_times(
        qi,
        mtime_age=mtime_source_age(src, now=now, active_age=active_age),
        recovery_evidence=recovery_evidence,
    )
    hb_age, claim_age, progress_age = active_claim_ages(
        now=now,
        stale=stale,
        claimed=claimed,
        hb=hb,
        progress_ts=progress_ts,
    )
    pid, pid_alive, heartbeat_fresh = active_claim_liveness(
        job=job,
        qi=qi,
        hb=hb,
        hb_age=hb_age,
        stale=stale,
        worker_liveness_checker=worker_liveness_checker,
    )
    return ActiveClaimState(
        job=job,
        queue_info=qi,
        hb_age=hb_age,
        claim_age=claim_age,
        progress_age=progress_age,
        pid=pid,
        pid_alive=pid_alive,
        heartbeat_fresh=heartbeat_fresh,
        timeout_expired=bool(claim_age >= file_timeout),
        checkpoint_stalled=bool(progress_age >= progress_stall and claim_age >= min(progress_stall, stale)),
        recovery_evidence=tuple(recovery_evidence),
    )


__all__ = ("ActiveClaimState", "load_active_claim_state")
