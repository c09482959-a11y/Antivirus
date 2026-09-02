"""Canonical raw-queue accumulator dependency ownership.

Raw accumulator state is queue-owned because it records deterministic
completion evidence for raw queue shards.  The previous canonical queue ownership modules imports
these concrete owners instead of defining accumulator dependency state itself.
"""
from __future__ import annotations

from Virus_Scan.scheduler.runtime.queue_json import (
    read_json_file as _queue_read_json_file,
    make_json_safe,
    validate_persistent_record_semantics,
    verify_persistent_json_file,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs
from Virus_Scan.runtime.api import runtime_value
from Virus_Scan.scheduler.api.contracts import RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.evidence.scheduler_json_writer import (
    RawQueueJsonDependencies,
    write_json_durable as _write_json_durable_impl,
)
from Virus_Scan.scheduler.queue.authority import raw_queue_dirs as _raw_queue_dirs_impl
from Virus_Scan.scheduler.queue.raw_accumulator_lock import GlobalRawAccumLock as _CanonicalGlobalRawAccumLock
from Virus_Scan.scheduler.queue.raw_queue_accumulator import (
    RawAccumulatorDependencies,
    RawAccumulatorStore as _CanonicalRawAccumulatorStore,
)
from Virus_Scan.scheduler.evidence.suppressed_failures import record_raw_queue_suppressed
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.yara.phase_contracts import normalize_yara_hits


def raw_json_dependencies() -> RawQueueJsonDependencies:
    return RawQueueJsonDependencies(
        make_json_safe=make_json_safe,
        validate_persistent_record_semantics=validate_persistent_record_semantics,
        verify_persistent_json_file=verify_persistent_json_file,
        runtime_value=runtime_value,
        record_suppressed=record_raw_queue_suppressed,
    )


def write_raw_json_durable(tmp: object, final: object, payload: object, *, log_context: str = "raw_json_publish", deps: object=None) -> bool:
    return _write_json_durable_impl(
        tmp,
        final,
        payload,
        log_context=log_context,
        deps=raw_json_dependencies() if deps is None else deps,
    )


def global_raw_dirs(queue_dir: object) -> object:
    return _raw_queue_dirs_impl(
        queue_dir,
        job_dirs=_queue_job_dirs,
        record_suppressed=record_raw_queue_suppressed,
    )


def raw_accumulator_dependencies() -> RawAccumulatorDependencies:
    return RawAccumulatorDependencies(
        global_raw_dirs=global_raw_dirs,
        read_json_file=_queue_read_json_file,
        write_json_durable=write_raw_json_durable,
        ordered_unique_tags=ordered_unique_tags,
        normalize_yara_hits=normalize_yara_hits,
        record_scheduler_suppressed=record_raw_queue_suppressed,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )


class RawAccumulatorStore(_CanonicalRawAccumulatorStore):
    """Queue-owned raw accumulator with explicit dependencies."""

    def __init__(self, queue_dir: object, file_id: object) -> None:
        super().__init__(queue_dir, file_id, raw_accumulator_dependencies())

    @classmethod
    def normalize_counts(cls, data: object, deps: object=None) -> object:
        return _CanonicalRawAccumulatorStore.normalize_counts(
            data,
            raw_accumulator_dependencies() if deps is None else deps,
        )

    @staticmethod
    def is_complete(data: object, deps: object=None) -> object:
        return _CanonicalRawAccumulatorStore.is_complete(
            data,
            raw_accumulator_dependencies() if deps is None else deps,
        )


class GlobalRawAccumLock(_CanonicalGlobalRawAccumLock):
    """Queue-owned raw accumulator lock with explicit dependencies."""

    def __init__(self, lock_dir: object, name: object, timeout: float = 30.0, *, deps: object=None) -> None:
        super().__init__(
            lock_dir,
            name,
            timeout,
            deps=raw_accumulator_dependencies() if deps is None else deps,
        )


__all__ = (
    "GlobalRawAccumLock",
    "RawAccumulatorStore",
    "global_raw_dirs",
    "raw_accumulator_dependencies",
    "raw_json_dependencies",
    "write_raw_json_durable",
)
