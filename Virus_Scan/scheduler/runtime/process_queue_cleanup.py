"""Process-queue runtime cleanup ownership."""
from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class ProcessQueueCleanupRequest:
    runtime_dir: object


@dataclass(frozen=True)
class ProcessQueueCleanupDependencies:
    report_suppressed: Callable[[str, BaseException], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


def cleanup_process_queue_runtime_dir(
    request: ProcessQueueCleanupRequest,
    deps: ProcessQueueCleanupDependencies,
) -> None:
    """Remove process-queue runtime artifacts under runtime ownership."""
    try:
        shutil.rmtree(request.runtime_dir, ignore_errors=True)
    except deps.recoverable_exceptions as suppressed_exc:
        try:
            deps.report_suppressed('monitor_loop_suppressed', suppressed_exc)
        except deps.recoverable_exceptions as reporting_exc:
            _ = reporting_exc
