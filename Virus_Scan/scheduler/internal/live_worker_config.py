"""Live in-memory worker configuration freezing.

Worker configuration carries scheduler-owned live IPC objects and callables used
inside the worker process.  Those values are not final JSON evidence values and
must not be converted to unsupported evidence before the worker can execute.
Non-live data remains recursively immutable through the canonical scheduler
evidence freezer.
"""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping, immutable_value
from Virus_Scan.scheduler.internal.immutable_output_support import (
    _materialize_scheduler_key,
    unsupported_scheduler_value_evidence,
)

_LIVE_WORKER_CONFIG_KEYS = frozenset((
    "cancel_table",
    "compiled_rules",
    "heartbeat_table",
    "stage_semaphores",
    "heartbeat_flags",
    "timeout_budget_factory",
    "timeout_result_annotator",
    "timeout_error_type",
    "progress_callback",
    "scan_session_snapshot",
    "routing_evidence_context",
))


def freeze_inmemory_worker_config(value: Mapping[str, object] | None) -> FrozenSchedulerMapping:
    """Freeze worker config while preserving scheduler-owned live dependencies."""
    if value is None:
        return FrozenSchedulerMapping()
    if type(value) is FrozenSchedulerMapping:
        return value
    items = no_hook_mapping_items(value)
    if items is None:
        return FrozenSchedulerMapping(((
            "worker_config_unavailable",
            unsupported_scheduler_value_evidence(value, field_name="worker_config"),
        ),))
    frozen: list[tuple[str, object]] = []
    for index, (key, item) in enumerate(items):
        materialized_key = _materialize_scheduler_key(key, index)
        if materialized_key in _LIVE_WORKER_CONFIG_KEYS:
            frozen.append((materialized_key, item))
        else:
            frozen.append((materialized_key, immutable_value(item)))
    return FrozenSchedulerMapping(tuple(sorted(frozen, key=lambda pair: pair[0])))


__all__ = ("freeze_inmemory_worker_config",)
