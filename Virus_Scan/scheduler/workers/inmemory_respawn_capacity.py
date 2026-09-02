"""Canonical schedulable-capacity owner for in-memory worker respawn."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_plain_instance_dict,
    no_hook_sequence_items,
)
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.inmemory_spawn_evidence import inmemory_process_alive_decision

_ZERO = 0


def _bounded_nonnegative_int(value: object, *, reason: str) -> int:
    parsed, parse_reason = scheduler_int(
        value,
        default=_ZERO,
        minimum=0,
        reason=reason,
    )
    return parsed if parse_reason == "" else _ZERO


def _worker_config_max_jobs(worker_config: object) -> int:
    items = no_hook_mapping_items(worker_config)
    if items is None:
        return _ZERO
    for key, value in items:
        if type(key) is str and str.__str__(key) == "max_jobs_per_worker":
            return _bounded_nonnegative_int(
                value,
                reason="inmemory_respawn_worker_config_max_jobs_per_worker_rejected",
            )
    return _ZERO


def _process_pid(proc: object) -> int | None:
    process_dict = no_hook_plain_instance_dict(proc)
    if process_dict is None:
        return None
    popen = process_dict.get("_popen")
    popen_dict = no_hook_plain_instance_dict(popen) if popen is not None else None
    pid_value = popen_dict.get("pid") if popen_dict is not None else process_dict.get("pid")
    pid, reason = scheduler_int(
        pid_value,
        default=_ZERO,
        minimum=1,
        reason="inmemory_respawn_process_pid_rejected",
    )
    return pid if reason == "" else None


def _worker_completed_jobs(worker_metrics: object, pid: int | None) -> int | None:
    if pid is None:
        return None
    metric_items = no_hook_mapping_items(worker_metrics)
    if metric_items is None:
        return None
    metric_record = None
    for key, value in metric_items:
        if type(key) is int and type(key) is not bool and key == pid:
            metric_record = value
            break
    row_items = no_hook_mapping_items(metric_record)
    if row_items is None:
        return None
    for key, value in row_items:
        if type(key) is str and str.__str__(key) == "completed_jobs":
            parsed, reason = scheduler_int(
                value,
                default=_ZERO,
                minimum=0,
                reason="inmemory_respawn_completed_jobs_rejected",
            )
            return parsed if reason == "" else None
    return None


def _process_is_schedulable(
    proc: object,
    *,
    worker_metrics: object,
    max_jobs_per_worker: int,
) -> bool:
    alive = inmemory_process_alive_decision(proc).alive
    if not alive:
        return alive
    if max_jobs_per_worker <= 0:
        return True
    completed_jobs = _worker_completed_jobs(worker_metrics, _process_pid(proc))
    if completed_jobs is None:
        return True
    return completed_jobs < max_jobs_per_worker


def schedulable_inmemory_worker_count(
    *,
    procs: object,
    worker_config: object,
    worker_metrics: object,
) -> int:
    """Return workers that can still accept another job under lifecycle policy."""
    max_jobs_per_worker = _worker_config_max_jobs(worker_config)
    count = 0
    for proc in no_hook_sequence_items(procs):
        if _process_is_schedulable(
            proc,
            worker_metrics=worker_metrics,
            max_jobs_per_worker=max_jobs_per_worker,
        ):
            count += 1
    return count


__all__ = ("schedulable_inmemory_worker_count",)
