"""Worker-owned process-queue dispatch request construction.

This module owns parent-side conversion from immutable dispatch input to the
canonical process-queue worker spawn request.  It keeps orchestration callers
away from subprocess command construction while avoiding mixed launch and
parent-dispatch ownership inside ``workers.spawn``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.workers.dispatch_value_support import (
    worker_dispatch_path,
    worker_dispatch_text,
)
from Virus_Scan.scheduler.workers.no_hook_scalars import worker_bool, worker_float, worker_int
from Virus_Scan.scheduler.workers.spawn import (
    ProcessQueueSpawnPublication,
    ProcessQueueWorkerSpawnRequest,
    spawn_and_publish_process_queue_worker,
)



_PATH_TYPE = type(Path("."))

@dataclass(frozen=True)
class ProcessQueueWorkerDispatchRequest:
    """Immutable parent-side dispatch request for one process-queue worker."""

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

    def __post_init__(self) -> None:
        object.__setattr__(self, "outputs_dir", worker_dispatch_path(self.outputs_dir, replacement_path="scheduler_worker_outputs_rejected"))
        object.__setattr__(self, "script_path", worker_dispatch_path(self.script_path, replacement_path="scheduler_worker_script_rejected.py"))
        object.__setattr__(self, "worker_index", worker_int(self.worker_index, replacement=0, minimum=0, reason="process_queue_worker_dispatch_index_rejected")[0])
        object.__setattr__(self, "python_executable", worker_dispatch_text(self.python_executable, replacement_text="python", reason="process_queue_worker_dispatch_python_rejected"))
        object.__setattr__(self, "env_base", immutable_mapping(self.env_base))
        object.__setattr__(self, "progress_every", worker_int(self.progress_every, replacement=1, minimum=1, reason="process_queue_worker_dispatch_progress_every_rejected")[0])
        object.__setattr__(self, "partial_output_every", worker_int(self.partial_output_every, replacement=0, minimum=0, reason="process_queue_worker_dispatch_partial_output_every_rejected")[0])
        object.__setattr__(self, "slow_file_warn_sec", worker_float(self.slow_file_warn_sec, replacement=0.0, minimum=0.0, reason="process_queue_worker_dispatch_slow_warn_rejected")[0])
        object.__setattr__(self, "per_file_timeout_sec", worker_float(self.per_file_timeout_sec, replacement=0.0, minimum=0.0, reason="process_queue_worker_dispatch_timeout_rejected")[0])
        object.__setattr__(self, "throttle_sec", worker_float(self.throttle_sec, replacement=0.0, minimum=0.0, reason="process_queue_worker_dispatch_throttle_rejected")[0])
        object.__setattr__(self, "strict", worker_bool(self.strict, replacement=False, reason="process_queue_worker_dispatch_strict_rejected")[0])
        if type(self.scan_session_manifest_path) is not _PATH_TYPE:
            raise TypeError("process_queue_worker_dispatch_manifest_path_required")


def dispatch_process_queue_worker(
    dispatch: ProcessQueueWorkerDispatchRequest,
    *,
    subprocess_stdin: Callable[[], object],
    windows_creationflags: Callable[..., int],
    log_error: Callable[[str], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> ProcessQueueSpawnPublication:
    """Build, launch, and publish one process-queue worker from immutable dispatch input."""
    request = ProcessQueueWorkerSpawnRequest(
        root=dispatch.root,
        queue_dir=dispatch.queue_dir,
        output=dispatch.outputs_dir
        / str.__add__(
            "worker_",
            str.__add__(str.zfill(int.__str__(dispatch.worker_index), 3), ".json"),
        ),
        worker_index=dispatch.worker_index,
        script_path=dispatch.script_path,
        python_executable=dispatch.python_executable,
        env_base=dispatch.env_base,
        progress_every=dispatch.progress_every,
        partial_output_every=dispatch.partial_output_every,
        slow_file_warn_sec=dispatch.slow_file_warn_sec,
        per_file_timeout_sec=dispatch.per_file_timeout_sec,
        throttle_sec=dispatch.throttle_sec,
        strict=dispatch.strict,
        scan_session_manifest_path=dispatch.scan_session_manifest_path,
    )
    return spawn_and_publish_process_queue_worker(
        request,
        subprocess_stdin=subprocess_stdin,
        windows_creationflags=windows_creationflags,
        log_error=log_error,
        recoverable_exceptions=recoverable_exceptions,
    )
