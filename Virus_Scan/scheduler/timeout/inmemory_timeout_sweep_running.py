"""Running-worker timeout decisions for in-memory timeout sweeps."""
from __future__ import annotations

from typing import Callable, Mapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running_budget import build_running_timeout_budget_state
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running_steps import evaluate_running_timeout_transition


def evaluate_running_timeout_state(
    *,
    jid: object,
    rec: Mapping[str, object],
    now: float,
    recovery: object,
    heartbeat_stale_sec: float,
    progress_stale_sec: float,
    base_pf_timeout: float,
    cancel_grace_sec: float,
    stage_is_pre_execution: Callable[[str], bool],
    update_ewma: Callable[..., object],
    ewma_state: dict[str, object],
    timeout_retry_evidence: list[Mapping[str, object]],
    timeout_reporting_failures: list[Mapping[str, object]],
    record_scheduler_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> tuple[int, int, int, int]:
    """Evaluate one running record and return timeout/orphan/stall counters."""
    state = build_running_timeout_budget_state(
        jid=jid,
        rec=rec,
        now=now,
        heartbeat_stale_sec=heartbeat_stale_sec,
        progress_stale_sec=progress_stale_sec,
        base_pf_timeout=base_pf_timeout,
        timeout_retry_evidence=timeout_retry_evidence,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return evaluate_running_timeout_transition(
        jid=jid,
        rec=rec,
        now=now,
        recovery=recovery,
        state=state,
        cancel_grace_sec=cancel_grace_sec,
        stage_is_pre_execution=stage_is_pre_execution,
        update_ewma=update_ewma,
        ewma_state=ewma_state,
        timeout_retry_evidence=timeout_retry_evidence,
        timeout_reporting_failures=timeout_reporting_failures,
        record_scheduler_suppressed=record_scheduler_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )


__all__ = ("evaluate_running_timeout_state",)
