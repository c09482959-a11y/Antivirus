"""Parent-side process-queue worker pool state publication.

The runner decides when workers are needed, but worker-pool state transitions
belong to worker ownership.  This module records immutable output/worker
snapshots after dispatch without embedding lifecycle mutation in the runner.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.internal.live_worker_entries import freeze_live_worker_entries
from Virus_Scan.scheduler.workers.dispatch_value_support import (
    worker_dispatch_path,
    worker_dispatch_text,
)
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_bool, worker_float, worker_int
from Virus_Scan.scheduler.workers.spawn_dispatch import ProcessQueueWorkerDispatchRequest, dispatch_process_queue_worker


_PATH_TYPE = type(Path("."))

@dataclass(frozen=True)
class ProcessQueueWorkerPoolRequest:
    root: object
    queue_dir: object
    outputs_dir: Path
    worker_index: int
    script_path: Path
    python_executable: str
    env_base: Mapping[str, str]
    progress_every: int
    partial_output_every: int
    slow_file_warn_sec: float
    per_file_timeout_sec: float
    throttle_sec: float
    strict: bool
    scan_session_manifest_path: Path
    current_outputs: tuple[object, ...]
    current_workers: tuple[tuple[int, object, object, tuple[str, ...]], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs_dir", worker_dispatch_path(self.outputs_dir, replacement_path="scheduler_worker_outputs_rejected"))
        object.__setattr__(self, "script_path", worker_dispatch_path(self.script_path, replacement_path="scheduler_worker_script_rejected.py"))
        object.__setattr__(
            self,
            "worker_index",
            worker_int(self.worker_index, replacement=0, minimum=0, reason="process_queue_worker_pool_index_rejected")[0],
        )
        object.__setattr__(self, "python_executable", worker_dispatch_text(self.python_executable, replacement_text="python", reason="process_queue_worker_pool_python_rejected"))
        object.__setattr__(self, "env_base", immutable_mapping(self.env_base))
        object.__setattr__(
            self,
            "progress_every",
            worker_int(self.progress_every, replacement=1, minimum=1, reason="process_queue_worker_pool_progress_every_rejected")[0],
        )
        object.__setattr__(
            self,
            "partial_output_every",
            worker_int(self.partial_output_every, replacement=0, minimum=0, reason="process_queue_worker_pool_partial_output_every_rejected")[0],
        )
        object.__setattr__(
            self,
            "slow_file_warn_sec",
            worker_float(self.slow_file_warn_sec, replacement=0.0, minimum=0.0, reason="process_queue_worker_pool_slow_warn_rejected")[0],
        )
        object.__setattr__(
            self,
            "per_file_timeout_sec",
            worker_float(self.per_file_timeout_sec, replacement=0.0, minimum=0.0, reason="process_queue_worker_pool_timeout_rejected")[0],
        )
        object.__setattr__(
            self,
            "throttle_sec",
            worker_float(self.throttle_sec, replacement=0.0, minimum=0.0, reason="process_queue_worker_pool_throttle_rejected")[0],
        )
        object.__setattr__(self, "strict", worker_bool(self.strict, replacement=False, reason="process_queue_worker_pool_strict_rejected")[0])
        if type(self.scan_session_manifest_path) is not _PATH_TYPE:
            raise TypeError("process_queue_worker_pool_manifest_path_required")
        object.__setattr__(self, "current_outputs", immutable_tuple(self.current_outputs))
        current_workers = () if self.current_workers is None else self.current_workers
        object.__setattr__(self, "current_workers", freeze_live_worker_entries(current_workers))


@dataclass(frozen=True)
class ProcessQueueWorkerPoolDependencies:
    subprocess_stdin: Callable[[], object]
    windows_creationflags: Callable[..., int]
    log_error: Callable[[str], object]
    recoverable_exceptions: tuple[type[BaseException], ...]


@dataclass(frozen=True)
class ProcessQueueWorkerPoolOutput:
    success: bool
    outputs: tuple[object, ...]
    workers: tuple[tuple[int, object, object, tuple[str, ...]], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "success", worker_bool(self.success, replacement=False, reason="process_queue_worker_pool_output_success_rejected")[0])
        object.__setattr__(self, "outputs", immutable_tuple(self.outputs))
        workers = () if self.workers is None else self.workers
        object.__setattr__(self, "workers", freeze_live_worker_entries(workers))


def publish_process_queue_worker_spawn(
    request: ProcessQueueWorkerPoolRequest,
    dependencies: ProcessQueueWorkerPoolDependencies,
) -> ProcessQueueWorkerPoolOutput:
    """Dispatch one worker and return immutable pool state snapshots."""

    publication = dispatch_process_queue_worker(
        ProcessQueueWorkerDispatchRequest(
            root=request.root,
            queue_dir=request.queue_dir,
            outputs_dir=request.outputs_dir,
            worker_index=request.worker_index,
            script_path=request.script_path,
            python_executable=request.python_executable,
            env_base=request.env_base,
            progress_every=request.progress_every,
            partial_output_every=request.partial_output_every,
            slow_file_warn_sec=request.slow_file_warn_sec,
            per_file_timeout_sec=request.per_file_timeout_sec,
            throttle_sec=request.throttle_sec,
            strict=request.strict,
            scan_session_manifest_path=request.scan_session_manifest_path,
        ),
        subprocess_stdin=dependencies.subprocess_stdin,
        windows_creationflags=dependencies.windows_creationflags,
        log_error=dependencies.log_error,
        recoverable_exceptions=dependencies.recoverable_exceptions,
    )
    outputs = (*tuple(request.current_outputs), publication.output)
    workers = tuple(request.current_workers)
    if publication.active_worker is not None:
        worker = publication.active_worker
        workers = (*workers, (worker.worker_index, worker.process, worker.output, tuple(worker.command)))
    return ProcessQueueWorkerPoolOutput(
        success=worker_bool(publication.success, replacement=False, reason="process_queue_worker_spawn_publication_success_rejected")[0],
        outputs=outputs,
        workers=workers,
    )


__all__ = ("ProcessQueueWorkerPoolDependencies", "ProcessQueueWorkerPoolOutput", "ProcessQueueWorkerPoolRequest", "publish_process_queue_worker_spawn")
