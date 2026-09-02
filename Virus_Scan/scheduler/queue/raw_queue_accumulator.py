"""Canonical raw accumulator ownership for the process raw queue.

The accumulator owns per-file raw evidence counters and durable publication.
Record normalization/merge transforms live in queue-owned raw_accumulator_records
so this module owns only durable store coordination and locking.
"""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, cast

from Virus_Scan.scheduler.queue.raw_accumulator_lock import GlobalRawAccumLock
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scheduler.queue.raw_accumulator_records import (
    append_result_record,
    coerce_nonnegative_int,
    empty_raw_accumulator,
    initialized_record,
    normalize_counts,
    reconciled_expected_record,
)


@dataclass(frozen=True)
class RawAccumulatorDependencies:
    global_raw_dirs: Callable[[object], tuple[Path, Path, Path, Path, Path, Path]]
    read_json_file: Callable[..., object]
    write_json_durable: Callable[..., bool]
    ordered_unique_tags: Callable[[object], list[str]]
    normalize_yara_hits: Callable[[object], list[str]]
    record_scheduler_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


class RawAccumulatorStore:
    """Atomic per-file raw evidence accumulator for the global work queue."""

    def __init__(self, queue_dir: object, file_id: object, deps: RawAccumulatorDependencies) -> None:
        if not isinstance(deps, RawAccumulatorDependencies):
            exception_message = "raw accumulator dependencies must be RawAccumulatorDependencies"
            raise TypeError(exception_message)
        self.deps = deps
        self.queue_dir = Path(cast("str | os.PathLike[str]", queue_dir))
        file_id_text, file_id_reason = no_hook_text(
            file_id,
            missing_reason="missing_raw_accumulator_file_id",
            unsupported_reason="unsafe_raw_accumulator_file_id_rejected",
        )
        self.file_id = file_id_text if not file_id_reason and file_id_text else "raw_accumulator_file_id_unavailable"
        *_unused, accum, locks = deps.global_raw_dirs(queue_dir)
        self.path = accum / (self.file_id + ".json")
        self.lock_dir = locks

    @classmethod
    def normalize_counts(cls, data: object, deps: RawAccumulatorDependencies) -> dict[str, object]:
        if not isinstance(deps, RawAccumulatorDependencies):
            exception_message = "raw accumulator dependencies must be RawAccumulatorDependencies"
            raise TypeError(exception_message)
        return normalize_counts(data, deps)

    def load(self) -> dict[str, object]:
        loaded = self.deps.read_json_file(self.path, default={})
        return self.normalize_counts({} if loaded is None else loaded, self.deps)

    def save(self, data: Mapping[str, object] | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        normalized = self.normalize_counts({} if data is None else data, self.deps)
        pid_text = int.__str__(os.getpid())
        tmp = self.path.with_suffix(self.path.suffix + "." + pid_text + ".tmp")
        if not self.deps.write_json_durable(tmp, self.path, normalized, log_context="raw_accumulator_save"):
            raise RuntimeError("raw accumulator save failed: " + Path.as_posix(self.path))

    def init(self, path: object, expected: int, initial_tags: list[object] | None = None, effective_stage: str = "unknown", ext_stage: str = "unknown", identity: Mapping[str, object] | None = None) -> dict[str, object]:
        with GlobalRawAccumLock(self.lock_dir, self.file_id, deps=self.deps):
            data = self.load()
            loaded_file_id = dict.get(data, "file_id")
            existing_expected = coerce_nonnegative_int(dict.get(data, "expected"), 0)
            requested_expected = coerce_nonnegative_int(expected, 0)
            if type(loaded_file_id) is str and loaded_file_id == self.file_id and existing_expected >= requested_expected:
                return data
            data = initialized_record(path, self.file_id, requested_expected, initial_tags, effective_stage, ext_stage, identity, self.deps)
            self.save(data)
            return data

    def append(self, result: Mapping[str, object] | None) -> dict[str, object]:
        with GlobalRawAccumLock(self.lock_dir, self.file_id, deps=self.deps):
            data = self.load() or empty_raw_accumulator(self.file_id)
            data = append_result_record(data, result, self.deps)
            self.save(data)
            return data

    def reconcile_expected(self, expected: int, *, reason: str = "raw_accumulator_expected_reconciled") -> dict[str, object]:
        with GlobalRawAccumLock(self.lock_dir, self.file_id, deps=self.deps):
            data = self.load() or {**empty_raw_accumulator(self.file_id), "degraded": True}
            data = reconciled_expected_record(data, expected, reason=reason, deps=self.deps)
            self.save(data)
            return data

    @staticmethod
    def is_complete(data: object, deps: RawAccumulatorDependencies) -> bool:
        items = no_hook_mapping_items(data)
        if items is None:
            unavailable_record = normalize_counts(data, deps)
            unavailable_reason = dict.get(unavailable_record, "raw_accumulator_unavailable_reason")
            reason_text = unavailable_reason if type(unavailable_reason) is str else "raw_accumulator_completion_record_unavailable"
            try:
                deps.record_scheduler_suppressed("raw_accumulator_completion_" + reason_text, RuntimeError(reason_text))
            except deps.recoverable_exceptions:
                return False
            return False
        raw_data = scheduler_str_key_mapping_from_items(items)
        normalized = RawAccumulatorStore.normalize_counts(raw_data, deps)
        expected = coerce_nonnegative_int(dict.get(normalized, "expected"), 0)
        completed = coerce_nonnegative_int(dict.get(normalized, "completed"), 0)
        return expected > 0 and completed >= expected


__all__ = ("RawAccumulatorDependencies", "RawAccumulatorStore")
