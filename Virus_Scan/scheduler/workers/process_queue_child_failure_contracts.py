"""Typed request contracts for process-queue child failure evidence."""
from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class ChildWorkerFailureResultRequest:
    job: Mapping[str, object] | None
    child_results: MutableMapping[str, object]
    worker_output_path: object
    queue_dir: object
    claim_path: object
    write_result: object
    log_error: object
    result: Mapping[str, object]
    failure_info: dict[str, object] | None
    done_count: int


@dataclass(frozen=True, slots=True)
class ChildLoopFailureRequest:
    job: Mapping[str, object] | None
    child_results: MutableMapping[str, object]
    worker_output_path: object
    queue_dir: object
    claim_path: object
    write_result: object
    log_error: object
    exc: BaseException
    done_count: int


__all__ = ("ChildLoopFailureRequest", "ChildWorkerFailureResultRequest")
