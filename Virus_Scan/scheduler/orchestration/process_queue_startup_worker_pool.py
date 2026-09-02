"""Worker-pool construction ownership for process-queue startup."""
from __future__ import annotations

from typing import TYPE_CHECKING

from Virus_Scan.runtime.api import runtime_value
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import monitor_bool
from Virus_Scan.scheduler.runtime.env_policy import scheduler_environment_snapshot
from Virus_Scan.scheduler.runtime.process_queue_environment import (
    ProcessQueueChildEnvironmentDependencies,
    ProcessQueueChildEnvironmentRequest,
    build_process_queue_child_environment,
)
from Virus_Scan.scheduler.runtime.queue_filesystem import scheduler_subprocess_stdin as _umige_subprocess_stdin, scheduler_windows_creationflags as _umige_windows_creationflags

if TYPE_CHECKING:
    from pathlib import Path


def build_process_queue_startup_worker_pool(
    *,
    root: str | Path,
    queue_dir: Path,
    outputs_dir: Path,
    scheduler_identity: object,
    dynamic_queue_feed: bool,
    progress_every: int,
    partial_output_every: int,
    slow_file_warn_sec: float,
    per_file_timeout_sec: float,
    throttle_sec: float,
    strict: bool,
    recoverable_exceptions: tuple[type[BaseException], ...],
    scan_session_manifest_path: Path,
) -> ProcessQueueParentWorkerPool:
    """Build the immutable parent worker-pool handle for startup."""
    env_output = build_process_queue_child_environment(
        ProcessQueueChildEnvironmentRequest(env=scheduler_environment_snapshot(), dynamic_queue_feed=monitor_bool(dynamic_queue_feed, default=False, reason="process_queue_worker_pool_dynamic_feed_rejected")),
        ProcessQueueChildEnvironmentDependencies(runtime_value=runtime_value),
    )
    return ProcessQueueParentWorkerPool(
        root=root,
        queue_dir=queue_dir,
        outputs_dir=outputs_dir,
        script_path=scheduler_identity.script_path,
        python_executable=scheduler_identity.python_executable,
        env_base=dict(env_output.env),
        progress_every=progress_every,
        partial_output_every=partial_output_every,
        slow_file_warn_sec=slow_file_warn_sec,
        per_file_timeout_sec=per_file_timeout_sec,
        throttle_sec=throttle_sec,
        strict=monitor_bool(strict, default=False, reason="process_queue_worker_pool_strict_rejected"),
        subprocess_stdin=_umige_subprocess_stdin,
        windows_creationflags=_umige_windows_creationflags,
        log_error=log_error,
        recoverable_exceptions=recoverable_exceptions,
        scan_session_manifest_path=scan_session_manifest_path,
    )
