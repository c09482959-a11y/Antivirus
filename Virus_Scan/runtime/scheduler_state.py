"""Canonical scheduler runtime state owner for Phase C shared-state collapse.

Scheduler planning facts were previously mirrored through ``runtime.shared_state``
from hot scheduler paths.  This module owns scheduler-session facts behind a
lock-protected API so runtime code does not publish mutable plan dictionaries
through any retired publication namespace.
"""
from __future__ import annotations

from threading import RLock
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.runtime.immutable_core import freeze_runtime_value


class SchedulerStateOwner:
    """Single mutation authority for scheduler-session facts."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._workload_queue_plan: MappingProxyType = MappingProxyType({})

    def publish_workload_plan(self, plan: Mapping[str, object] | None) -> MappingProxyType:
        frozen = freeze_runtime_value({} if plan is None else plan)
        if type(frozen) is not MappingProxyType:
            frozen = freeze_runtime_value(
                {
                    "value": None,
                    "unavailable_reason": "scheduler_workload_plan_mapping_rejected",
                }
            )
        with self._lock:
            if type(frozen) is not MappingProxyType:
                raise TypeError("scheduler_workload_plan_freeze_failed")
            self._workload_queue_plan = frozen
            return self._workload_queue_plan

    def workload_plan(self) -> MappingProxyType:
        with self._lock:
            return self._workload_queue_plan

    def snapshot(self) -> MappingProxyType:
        with self._lock:
            return freeze_runtime_value(
                {"UMIGE_WORKLOAD_QUEUE_PLAN": self._workload_queue_plan}
            )


_SCHEDULER_STATE = SchedulerStateOwner()


def publish_workload_queue_plan(plan: Mapping[str, object] | None) -> MappingProxyType:
    return _SCHEDULER_STATE.publish_workload_plan(plan)


__all__ = (
    "SchedulerStateOwner", "publish_workload_queue_plan",
)
