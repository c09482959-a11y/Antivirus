"""In-memory dead-worker recovery ownership."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, MutableSet, Sequence

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_plain_instance_dict, no_hook_sequence_items
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.internal.no_hook_methods import safe_scheduler_bound_method

_SCHEDULER_ZERO_INT = 0


@dataclass(frozen=True, slots=True)
class InMemoryWorkerDeathSweep:
    dead_pids: tuple[int, ...]
    retried_jobs: tuple[int, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "dead_pids", _owned_int_tuple(self.dead_pids))
        object.__setattr__(self, "retried_jobs", _owned_int_tuple(self.retried_jobs))


@dataclass(frozen=True, slots=True)
class InMemoryWorkerLivenessSnapshot:
    live_count: int
    dead_pids: tuple[int, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "dead_pids", _owned_int_tuple(self.dead_pids))


def _owned_int_tuple(values: object) -> tuple[int, ...]:
    parsed_values: list[int] = []
    for value in no_hook_sequence_items(values):
        parsed, reason = scheduler_int(
            value,
            default=_SCHEDULER_ZERO_INT,
            minimum=0,
            reason="inmemory_worker_death_integer_rejected",
        )
        if reason == "":
            parsed_values.append(parsed)
    return tuple(parsed_values)


@dataclass(frozen=True, slots=True)
class InMemoryWorkerProcessPidDecision:
    pid: int | None
    reason: str
    accepted: bool
    source_is_plain_state: bool

    def as_pid(self) -> int | None:
        return self.pid


def _process_pid_decision(proc: object) -> InMemoryWorkerProcessPidDecision:
    state = no_hook_plain_instance_dict(proc)
    if state is None:
        return InMemoryWorkerProcessPidDecision(None, "inmemory_worker_process_state_unavailable", accepted=False, source_is_plain_state=False)
    raw_pid = dict.get(state, "pid")
    pid, reason = scheduler_int(
        raw_pid,
        default=_SCHEDULER_ZERO_INT,
        minimum=0,
        reason="inmemory_worker_pid_rejected",
    )
    if reason != "":
        return InMemoryWorkerProcessPidDecision(None, reason, accepted=False, source_is_plain_state=True)
    return InMemoryWorkerProcessPidDecision(pid, "", accepted=True, source_is_plain_state=True)


def _process_pid(proc: object) -> int | None:
    return _process_pid_decision(proc).as_pid()


def snapshot_inmemory_worker_liveness(*, procs: Sequence[object]) -> InMemoryWorkerLivenessSnapshot:
    """Return immutable liveness evidence for in-memory worker processes."""
    live = 0
    dead: list[int] = []
    for proc in no_hook_sequence_items(procs):
        pid = _process_pid(proc)
        if pid is None:
            continue
        is_alive, alive_reason = safe_scheduler_bound_method(
            proc,
            "is_alive",
            reason_prefix="unsafe_inmemory_worker_liveness",
        )
        if alive_reason or is_alive is None:
            continue
        if is_alive() is True:
            live += 1
        else:
            dead.append(pid)
    return InMemoryWorkerLivenessSnapshot(live, tuple(dead))


def retry_jobs_owned_by_dead_workers(*, procs: Sequence[object], active: Mapping[int, Mapping[str, object]], terminal: MutableSet[int], retry_job: Callable[..., object]) -> InMemoryWorkerDeathSweep:
    """Retry active jobs whose owning worker process died.

    Reconciliation owns the dead-worker recovery decision. The caller retains
    live queue/retry authority through the explicit retry_job callback.
    """
    dead_pids = snapshot_inmemory_worker_liveness(procs=procs).dead_pids
    if not dead_pids:
        return InMemoryWorkerDeathSweep((), ())
    dead_pid_set = frozenset(dead_pids)
    retried = []
    active_items = no_hook_mapping_items(active)
    if active_items is None:
        return InMemoryWorkerDeathSweep(dead_pids, ())
    for job_id, info in active_items:
        pid = scheduler_mapping_value(info, "pid", default=None)
        parsed_pid, pid_reason = scheduler_int(
            pid,
            default=_SCHEDULER_ZERO_INT,
            minimum=0,
            reason="inmemory_worker_dead_pid_rejected",
        )
        parsed_job_id, job_reason = scheduler_int(
            job_id,
            default=_SCHEDULER_ZERO_INT,
            minimum=0,
            reason="inmemory_worker_dead_job_id_rejected",
        )
        if (
            pid_reason == ""
            and job_reason == ""
            and parsed_pid in dead_pid_set
            and parsed_job_id not in terminal
        ):
            retry_job(parsed_job_id, "worker_died", pid=parsed_pid)
            retried.append(parsed_job_id)
    return InMemoryWorkerDeathSweep(dead_pids, tuple(retried))


__all__ = (
    "InMemoryWorkerDeathSweep",
    "InMemoryWorkerLivenessSnapshot",
    "InMemoryWorkerProcessPidDecision",
    "_process_pid_decision",
    "retry_jobs_owned_by_dead_workers",
    "snapshot_inmemory_worker_liveness",
)
