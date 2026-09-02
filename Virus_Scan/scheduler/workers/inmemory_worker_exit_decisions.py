"""Typed no-hook decisions for in-memory worker-exit reconciliation."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items_status,
    no_hook_sequence_items,
)
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_mapping_item_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int


@dataclass(frozen=True, slots=True)
class WorkerExitPidDecision:
    """Replayable worker-exit pid parse result."""

    pid: int
    accepted: bool
    reason: str


@dataclass(frozen=True, slots=True)
class WorkerExitActiveItemsDecision:
    """Replayable active-worker mapping materialization result."""

    items: tuple[tuple[object, object], ...]
    accepted: bool
    reason: str


@dataclass(frozen=True, slots=True)
class WorkerExitTerminalIdsDecision:
    """Replayable terminal-job id materialization result."""

    job_ids: frozenset[int]
    accepted: bool
    reason: str


def worker_exit_positive_int_decision(value: object, *, reason: str, missing_reason: str) -> WorkerExitPidDecision:
    if value is None:
        return WorkerExitPidDecision(0, accepted=False, reason=missing_reason)
    parsed, parse_reason = scheduler_int(value, default=0, minimum=0, reason=reason)
    if parse_reason != "":
        return WorkerExitPidDecision(0, accepted=False, reason=parse_reason)
    if parsed <= 0:
        return WorkerExitPidDecision(0, accepted=False, reason=reason)
    return WorkerExitPidDecision(parsed, accepted=True, reason="")


def active_worker_items_decision(active: object) -> WorkerExitActiveItemsDecision:
    if active is None:
        return WorkerExitActiveItemsDecision((), accepted=True, reason="worker_exit_active_missing")
    items, _materialize_reason = no_hook_mapping_items_status(active)
    if items is None:
        return WorkerExitActiveItemsDecision((), accepted=False, reason="worker_exit_active_mapping_rejected")
    return WorkerExitActiveItemsDecision(tuple(items), accepted=True, reason="")


def terminal_job_ids_decision(terminal: object) -> WorkerExitTerminalIdsDecision:
    if type(terminal) not in {set, frozenset}:
        return WorkerExitTerminalIdsDecision(frozenset(), accepted=False, reason="worker_exit_terminal_set_rejected")
    out: set[int] = set()
    for item in terminal:
        parsed = worker_exit_positive_int_decision(
            item,
            reason="worker_exit_terminal_job_id_rejected",
            missing_reason="worker_exit_terminal_job_id_missing",
        )
        if parsed.accepted:
            out.add(parsed.pid)
    return WorkerExitTerminalIdsDecision(frozenset(out), accepted=True, reason="")


def info_pid_decision(info: object) -> WorkerExitPidDecision:
    items, _materialize_reason = no_hook_mapping_items_status(info)
    if items is None:
        return WorkerExitPidDecision(0, accepted=False, reason="worker_exit_owner_mapping_rejected")
    missing = object()
    value = scheduler_mapping_item_value(items, "pid", missing)
    if value is missing:
        return WorkerExitPidDecision(0, accepted=False, reason="worker_exit_owner_pid_missing")
    return worker_exit_positive_int_decision(
        value,
        reason="worker_exit_owner_pid_rejected",
        missing_reason="worker_exit_owner_pid_missing",
    )


def worker_exit_pid_decision_from_message(message: object) -> WorkerExitPidDecision:
    items = no_hook_sequence_items(message)
    if len(items) < 4:
        return WorkerExitPidDecision(0, accepted=False, reason="worker_exit_message_pid_missing")
    return worker_exit_positive_int_decision(
        items[3],
        reason="worker_exit_message_pid_rejected",
        missing_reason="worker_exit_message_pid_missing",
    )


__all__ = (
    "WorkerExitActiveItemsDecision",
    "WorkerExitPidDecision",
    "WorkerExitTerminalIdsDecision",
    "active_worker_items_decision",
    "info_pid_decision",
    "terminal_job_ids_decision",
    "worker_exit_pid_decision_from_message",
    "worker_exit_positive_int_decision",
)
