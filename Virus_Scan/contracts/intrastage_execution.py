"""Immutable concurrency plan for one scan-session intrastage executor owner."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from Virus_Scan.contracts.text_boundaries import exact_bounded_text

INTRASTAGE_EXECUTION_PLAN_SCHEMA_VERSION = "intrastage_execution_plan_v1"
_ALLOWED_BACKENDS = frozenset({"thread", "process"})


def _exact_int(value: object, reason: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or type(value) is bool:
        raise TypeError(reason)
    if value < minimum or value > maximum:
        raise ValueError(reason)
    return value


@dataclass(frozen=True, slots=True)
class IntrastageExecutionPlan:
    """Exact immutable executor/backpressure plan bound to a session generation."""

    scheduler_mode: str
    scheduler_worker_count: int
    stage_parallel_enabled: bool
    intrastage_enabled: bool
    default_backend: str
    intrastage_workers: int
    serial_task_threshold: int
    max_pending_tasks: int
    max_process_task_bytes: int
    schema_version: str = INTRASTAGE_EXECUTION_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        scheduler_mode = exact_bounded_text(
            self.scheduler_mode,
            "intrastage_scheduler_mode_invalid",
            maximum=64,
        ).lower()
        scheduler_workers = _exact_int(
            self.scheduler_worker_count,
            "intrastage_scheduler_worker_count_invalid",
            minimum=0,
            maximum=4096,
        )
        if type(self.stage_parallel_enabled) is not bool:
            raise TypeError("intrastage_stage_parallel_enabled_invalid")
        if type(self.intrastage_enabled) is not bool:
            raise TypeError("intrastage_enabled_invalid")
        backend = exact_bounded_text(
            self.default_backend,
            "intrastage_default_backend_invalid",
            maximum=16,
        ).lower()
        if backend not in _ALLOWED_BACKENDS:
            raise ValueError("intrastage_default_backend_invalid")
        workers = _exact_int(
            self.intrastage_workers,
            "intrastage_worker_count_invalid",
            minimum=1,
            maximum=256,
        )
        serial_threshold = _exact_int(
            self.serial_task_threshold,
            "intrastage_serial_threshold_invalid",
            minimum=1,
            maximum=64,
        )
        max_pending = _exact_int(
            self.max_pending_tasks,
            "intrastage_max_pending_invalid",
            minimum=workers,
            maximum=4096,
        )
        max_process_task_bytes = _exact_int(
            self.max_process_task_bytes,
            "intrastage_max_process_task_bytes_invalid",
            minimum=4096,
            maximum=16 * 1024 * 1024,
        )
        schema = exact_bounded_text(
            self.schema_version,
            "intrastage_plan_schema_invalid",
            maximum=128,
        )
        if schema != INTRASTAGE_EXECUTION_PLAN_SCHEMA_VERSION:
            raise ValueError("intrastage_plan_schema_invalid")
        object.__setattr__(self, "scheduler_mode", scheduler_mode)
        object.__setattr__(self, "scheduler_worker_count", scheduler_workers)
        object.__setattr__(self, "default_backend", backend)
        object.__setattr__(self, "intrastage_workers", workers)
        object.__setattr__(self, "serial_task_threshold", serial_threshold)
        object.__setattr__(self, "max_pending_tasks", max_pending)
        object.__setattr__(self, "max_process_task_bytes", max_process_task_bytes)
        object.__setattr__(self, "schema_version", schema)

    @property
    def parallel_enabled(self) -> bool:
        return self.stage_parallel_enabled and self.intrastage_enabled and self.intrastage_workers > 1

    def to_record(self) -> dict[str, object]:
        return {
            "default_backend": self.default_backend,
            "intrastage_enabled": self.intrastage_enabled,
            "intrastage_workers": self.intrastage_workers,
            "max_pending_tasks": self.max_pending_tasks,
            "max_process_task_bytes": self.max_process_task_bytes,
            "scheduler_mode": self.scheduler_mode,
            "scheduler_worker_count": self.scheduler_worker_count,
            "schema_version": self.schema_version,
            "serial_task_threshold": self.serial_task_threshold,
            "stage_parallel_enabled": self.stage_parallel_enabled,
        }

    @property
    def digest(self) -> str:
        raw = json.dumps(
            self.to_record(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def from_record(cls, record: object) -> "IntrastageExecutionPlan":
        if type(record) is not dict:
            raise TypeError("intrastage_plan_record_invalid")
        expected = {
            "default_backend",
            "intrastage_enabled",
            "intrastage_workers",
            "max_pending_tasks",
            "max_process_task_bytes",
            "scheduler_mode",
            "scheduler_worker_count",
            "schema_version",
            "serial_task_threshold",
            "stage_parallel_enabled",
        }
        if set(record) != expected:
            raise ValueError("intrastage_plan_record_keys_invalid")
        return cls(
            scheduler_mode=record["scheduler_mode"],
            scheduler_worker_count=record["scheduler_worker_count"],
            stage_parallel_enabled=record["stage_parallel_enabled"],
            intrastage_enabled=record["intrastage_enabled"],
            default_backend=record["default_backend"],
            intrastage_workers=record["intrastage_workers"],
            serial_task_threshold=record["serial_task_threshold"],
            max_pending_tasks=record["max_pending_tasks"],
            max_process_task_bytes=record["max_process_task_bytes"],
            schema_version=record["schema_version"],
        )


__all__ = (
    "INTRASTAGE_EXECUTION_PLAN_SCHEMA_VERSION",
    "IntrastageExecutionPlan",
)
