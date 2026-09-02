"""Callable contracts for canonical scheduler checkpoint publication."""
from __future__ import annotations

from collections.abc import MutableMapping
from typing import Protocol

from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache

PipelineResults = MutableMapping[object, object]


class TimeProvider(Protocol):
    def __call__(self) -> float: ...


class EnvironmentGetter(Protocol):
    def __call__(self, name: str, default: object = None) -> object: ...


class JsonSafeMaterializer(Protocol):
    def __call__(self, value: object) -> object: ...


class ErrorLogger(Protocol):
    def __call__(self, message: str) -> object: ...


class PartialScanWriter(Protocol):
    def __call__(self, path: str, results: object, *, make_json_safe: object = None) -> bool: ...


class PartialSchedulerWriter(Protocol):
    def __call__(
        self,
        *,
        partial_output_path: object,
        results: PipelineResults,
        total_files: int,
        partial_output_every: int | str | None,
        last_partial_write: float,
        now: TimeProvider,
        environ_get: EnvironmentGetter,
        write_partial_scan_results: PartialScanWriter,
        make_json_safe: JsonSafeMaterializer,
        log_error: ErrorLogger,
        checkpoint_cache: PartialCheckpointCache | None = None,
        force: bool = False,
    ) -> float: ...


__all__ = (
    "EnvironmentGetter",
    "ErrorLogger",
    "JsonSafeMaterializer",
    "PartialScanWriter",
    "PartialSchedulerWriter",
    "PipelineResults",
    "TimeProvider",
)
