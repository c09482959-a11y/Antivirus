"""Lifecycle-owned scheduler runtime coordination state.

This module replaces function-level ``global`` rebinding in scheduler entry
points with explicit owner state.  The owner is intentionally small: it tracks
per-run profile deferral/flush policy and child-worker stage tables without
adding alternate paths, secondary layers, or import-time mutation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_json_key,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.runtime.governance_inputs import runtime_bool, runtime_int
from Virus_Scan.runtime.immutable_core import freeze_runtime_value


def _stage_table_evidence(reason: str, value: object, *, table_name: str) -> dict[str, object]:
    return {
        "stage": "stage_budget",
        "state": "failed",
        "error_category": reason,
        "error_source": "runtime.scheduler_runtime_state",
        "message": reason,
        "context": {
            "table_name": table_name,
            "value_type": no_hook_type_name(value),
        },
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
        "fatal": False,
    }


def _copy_live_stage_table(
    table: Mapping[str, object] | None,
    *,
    table_name: str,
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    """Copy scheduler-owned live stage tables without freezing runtime carriers.

    Stage semaphores are live synchronization objects owned by scheduler runtime
    state, not durable evidence snapshots.  Only exact dict / mappingproxy-backed
    mappings are copied; unknown mapping subclasses are rejected without probing
    caller-owned mapping hooks.
    """
    if table is None:
        return {}, (
            _stage_table_evidence(
                "scheduler_stage_table_missing",
                table,
                table_name=table_name,
            ),
        )
    items = no_hook_mapping_items(table)
    if items is None:
        return {}, (
            _stage_table_evidence(
                "scheduler_stage_table_mapping_rejected",
                table,
                table_name=table_name,
            ),
        )
    copied: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for index, (key, value) in enumerate(items):
        key_text, key_reason = no_hook_json_key(key, index, prefix="scheduler_stage_table_key")
        if key_reason or key_text == "":
            failures.append(
                _stage_table_evidence(
                    key_reason or "scheduler_stage_table_key_rejected",
                    key,
                    table_name=table_name,
                )
            )
            continue
        copied[key_text] = value
    return copied, tuple(failures)


def _scheduler_config_evidence(value: object) -> tuple[dict[str, object], ...]:
    failures: list[dict[str, object]] = []
    if value is None:
        return ()
    if type(value) not in (tuple, list, set, frozenset):
        return (
            _stage_table_evidence(
                "scheduler_config_evidence_sequence_rejected",
                value,
                table_name="scheduler_config_evidence",
            ),
        )
    for item in no_hook_sequence_items(value):
        items = no_hook_mapping_items(item)
        if items is None:
            failures.append(
                _stage_table_evidence(
                    "scheduler_config_evidence_rejected",
                    item,
                    table_name="scheduler_config_evidence",
                )
            )
            continue
        failures.append(dict(items))
    return tuple(failures)


def _scheduler_stage_tables_proxy(
    stage_limits: Mapping[str, object],
    stage_semaphores: Mapping[str, object],
    stage_table_evidence: tuple[Mapping[str, object], ...],
) -> Mapping[str, object]:
    snapshot: dict[str, object] = {
        "stage_limits": freeze_runtime_value(stage_limits),
        "stage_semaphores": MappingProxyType(dict(stage_semaphores)),
        "stage_table_evidence": tuple(stage_table_evidence),
    }
    return MappingProxyType(snapshot)


@dataclass(frozen=True)
class SchedulerProfilePolicySnapshot:
    """Immutable snapshot used to restore scheduler profile policy."""

    defer_profile_writes: bool
    profile_flush_every: int

    def __post_init__(self) -> None:
        if type(self) is not SchedulerProfilePolicySnapshot:
            exception_message = "scheduler profile policy snapshot owner rejected"
            raise TypeError(exception_message)
        defer, defer_issues = runtime_bool(
            self.defer_profile_writes,
            field_name="scheduler_defer_profile_writes",
        )
        flush, flush_issues = runtime_int(
            self.profile_flush_every,
            field_name="scheduler_profile_flush_every",
            default=1,
        )
        if defer_issues or flush_issues:
            exception_message = "scheduler profile policy snapshot rejected"
            raise ValueError(exception_message)
        object.__setattr__(self, "defer_profile_writes", defer)
        object.__setattr__(self, "profile_flush_every", max(1, flush))


@dataclass
class SchedulerRuntimeState:
    """Thread-safe owner for scheduler runtime coordination settings."""

    defer_profile_writes: bool = False
    profile_flush_every: int = 1
    stage_limits: dict[str, object] = field(default_factory=dict)
    stage_semaphores: dict[str, object] = field(default_factory=dict)
    stage_table_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)
    raw_stage_exec_cache: dict[str, object] = field(default_factory=dict)
    raw_stage_exec_cache_max: int = 2048
    lock: RLock = field(default_factory=RLock)

    def configure_profile_policy(
        self,
        *,
        defer_profile_writes: bool,
        profile_flush_every: int,
        bulk_profile_flush_every: int,
    ) -> SchedulerProfilePolicySnapshot:
        """Set explicit profile persistence policy for one scheduler run."""
        defer, defer_issues = runtime_bool(
            defer_profile_writes,
            field_name="scheduler_defer_profile_writes",
        )
        flush, flush_issues = runtime_int(
            profile_flush_every,
            field_name="scheduler_profile_flush_every",
            default=1,
        )
        bulk_flush, bulk_issues = runtime_int(
            bulk_profile_flush_every,
            field_name="scheduler_bulk_profile_flush_every",
            default=1,
        )
        if defer_issues or flush_issues or bulk_issues:
            exception_message = "scheduler profile policy rejected"
            raise ValueError(exception_message)
        with self.lock:
            previous = SchedulerProfilePolicySnapshot(
                defer_profile_writes=self.defer_profile_writes,
                profile_flush_every=self.profile_flush_every,
            )
            self.defer_profile_writes = defer
            next_flush = max(1, flush)
            if self.defer_profile_writes:
                next_flush = max(1, flush, bulk_flush)
            self.profile_flush_every = next_flush
            return previous

    def restore_profile_policy(self, snapshot: SchedulerProfilePolicySnapshot) -> None:
        """Restore a policy captured before a scheduler run."""
        if type(snapshot) is not SchedulerProfilePolicySnapshot:
            exception_message = "scheduler profile policy snapshot rejected"
            raise TypeError(exception_message)
        with self.lock:
            self.defer_profile_writes = snapshot.defer_profile_writes
            self.profile_flush_every = snapshot.profile_flush_every

    def configure_worker_stage_tables(
        self,
        *,
        stage_limits: Mapping[str, object] | None,
        stage_semaphores: Mapping[str, object] | None,
        failure_evidence: object = (),
    ) -> None:
        """Replace worker stage tables through the lifecycle owner."""
        with self.lock:
            copied_limits, limit_failures = _copy_live_stage_table(
                stage_limits,
                table_name="stage_limits",
            )
            copied_semaphores, semaphore_failures = _copy_live_stage_table(
                stage_semaphores,
                table_name="stage_semaphores",
            )
            self.stage_limits = dict(freeze_runtime_value(copied_limits))
            self.stage_semaphores = copied_semaphores
            self.stage_table_evidence = tuple(
                freeze_runtime_value(item)
                for item in (
                    *_scheduler_config_evidence(failure_evidence),
                    *limit_failures,
                    *semaphore_failures,
                )
            )


    def configure_raw_stage_cache(self, *, max_entries: int) -> None:
        """Configure the lifecycle-owned raw-stage execution cache."""
        limit, issues = runtime_int(
            max_entries,
            field_name="scheduler_raw_stage_cache_max_entries",
            default=0,
        )
        if issues:
            exception_message = "scheduler raw-stage cache limit rejected"
            raise ValueError(exception_message)
        with self.lock:
            self.raw_stage_exec_cache_max = limit
            if self.raw_stage_exec_cache_max == 0:
                self.raw_stage_exec_cache.clear()
            elif len(self.raw_stage_exec_cache) > self.raw_stage_exec_cache_max:
                overflow = len(self.raw_stage_exec_cache) - self.raw_stage_exec_cache_max
                cache_items = no_hook_mapping_items(self.raw_stage_exec_cache) or ()
                for key, _value in cache_items[:overflow]:
                    self.raw_stage_exec_cache.pop(key, None)

    def raw_stage_cache_get(self, key: object) -> object | None:
        """Return a cached raw-stage result through scheduler-owned state."""
        text, reason = no_hook_text(
            key,
            missing_reason="scheduler_raw_stage_cache_key_missing",
            unsupported_reason="scheduler_raw_stage_cache_key_rejected",
        )
        if reason or text == "":
            return None
        with self.lock:
            return self.raw_stage_exec_cache.get(text)

    def raw_stage_cache_put(self, key: object, value: object) -> None:
        """Store a raw-stage result through scheduler-owned state."""
        text, reason = no_hook_text(
            key,
            missing_reason="scheduler_raw_stage_cache_key_missing",
            unsupported_reason="scheduler_raw_stage_cache_key_rejected",
        )
        if reason or text == "":
            return
        with self.lock:
            if self.raw_stage_exec_cache_max <= 0:
                return
            self.raw_stage_exec_cache[text] = freeze_runtime_value(value)
            if len(self.raw_stage_exec_cache) > self.raw_stage_exec_cache_max:
                overflow = max(1, len(self.raw_stage_exec_cache) - self.raw_stage_exec_cache_max)
                cache_items = no_hook_mapping_items(self.raw_stage_exec_cache) or ()
                for old_key, _value in cache_items[:overflow]:
                    self.raw_stage_exec_cache.pop(old_key, None)

    def raw_stage_cache_snapshot(self) -> Mapping[str, object]:
        """Return an immutable raw-stage cache snapshot for diagnostics."""
        with self.lock:
            return freeze_runtime_value(self.raw_stage_exec_cache)

    def stage_tables_snapshot(self) -> Mapping[str, object]:
        """Return immutable stage table snapshots for diagnostics/tests."""
        with self.lock:
            return _scheduler_stage_tables_proxy(
                self.stage_limits,
                self.stage_semaphores,
                tuple(self.stage_table_evidence),
            )


_SCHEDULER_RUNTIME_STATE = SchedulerRuntimeState()


def scheduler_runtime_state() -> SchedulerRuntimeState:
    return _SCHEDULER_RUNTIME_STATE


__all__ = (
    "SchedulerProfilePolicySnapshot",
    "SchedulerRuntimeState",
    "scheduler_runtime_state",
)
