"""Process-queue parent worker-pool state ownership.

This orchestration module owns the parent-side worker/output collections used by
process-queue execution.  The execution loop requests worker spawns and active
worker pruning through this bounded state owner instead of mutating raw worker
lists directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.scheduler.internal.immutable_output_support import frozen_scheduler_items_decision
from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_sequence_items, scheduler_str_text_mapping_from_items
from Virus_Scan.scheduler.orchestration.process_queue_monitor_no_hook import (
    monitor_bool,
    monitor_float,
    monitor_int,
    monitor_recoverable_exceptions,
)

from Virus_Scan.scheduler.workers.process_queue_worker_pool import (
    ProcessQueueWorkerPoolDependencies,
    ProcessQueueWorkerPoolRequest,
    publish_process_queue_worker_spawn,
)


_PATH_TYPE = type(Path("."))


def _copy_exact_env(value: object) -> dict[str, str]:
    frozen_decision = frozen_scheduler_items_decision(value)
    items = frozen_decision.items if frozen_decision.accepted else None
    if items is None:
        items = no_hook_mapping_items(value)
    if items is None:
        return {}
    return scheduler_str_text_mapping_from_items(items)


def _copy_exact_outputs(value: object) -> list[Path]:
    return [item for item in no_hook_sequence_items(value) if type(item) is _PATH_TYPE]


def _copy_exact_workers(value: object) -> list[tuple[int, object, Path, list[str]]]:
    out: list[tuple[int, object, Path, list[str]]] = []
    for row in no_hook_sequence_items(value):
        if type(row) not in {tuple, list} or len(row) < 4:
            continue
        idx, proc, output, cmd = row[0], row[1], row[2], row[3]
        if type(output) is not _PATH_TYPE:
            continue
        command = list(scheduler_str_sequence_items(cmd))
        out.append((monitor_int(idx, default=0, minimum=0, reason="process_queue_worker_pool_index_rejected"), proc, output, command))
    return out


@dataclass
class ProcessQueueParentWorkerPool:
    """Explicit parent-owned process-queue worker/output state."""

    root: str | Path
    queue_dir: Path
    outputs_dir: Path
    script_path: str | Path
    python_executable: str | Path
    env_base: dict[str, str]
    progress_every: int
    partial_output_every: int
    slow_file_warn_sec: float
    per_file_timeout_sec: float
    throttle_sec: float
    strict: bool
    subprocess_stdin: Callable[[], object]
    windows_creationflags: Callable[[], int]
    log_error: Callable[[str], object]
    recoverable_exceptions: tuple[type[BaseException], ...]
    scan_session_manifest_path: Path
    outputs: list[Path] = field(default_factory=list)
    workers: list[tuple[int, object, Path, list[str]]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.env_base = _copy_exact_env(self.env_base)
        self.outputs = _copy_exact_outputs(self.outputs)
        self.workers = _copy_exact_workers(self.workers)
        self.progress_every = monitor_int(self.progress_every, default=1, minimum=1, reason="process_queue_worker_pool_progress_every_rejected")
        self.partial_output_every = monitor_int(self.partial_output_every, default=0, minimum=0, reason="process_queue_worker_pool_partial_every_rejected")
        self.slow_file_warn_sec = monitor_float(self.slow_file_warn_sec, default=0.0, minimum=0.0, reason="process_queue_worker_pool_slow_warn_rejected")
        self.per_file_timeout_sec = monitor_float(self.per_file_timeout_sec, default=0.0, minimum=0.0, reason="process_queue_worker_pool_timeout_rejected")
        self.throttle_sec = monitor_float(self.throttle_sec, default=0.0, minimum=0.0, reason="process_queue_worker_pool_throttle_rejected")
        self.strict = monitor_bool(self.strict, default=False, reason="process_queue_worker_pool_strict_rejected")
        self.recoverable_exceptions = monitor_recoverable_exceptions(self.recoverable_exceptions)
        if type(self.scan_session_manifest_path) is not _PATH_TYPE:
            raise TypeError("process_queue_worker_pool_manifest_path_required")

    def spawn(self, worker_index: int) -> bool:
        """Spawn one process-queue worker and update bounded parent state."""

        pool_output = publish_process_queue_worker_spawn(
            ProcessQueueWorkerPoolRequest(
                root=self.root,
                queue_dir=self.queue_dir,
                outputs_dir=self.outputs_dir,
                worker_index=worker_index,
                script_path=Path(self.script_path),
                python_executable=str.__str__(self.python_executable) if type(self.python_executable) is str else str(Path(self.python_executable)),
                env_base=self.env_base,
                progress_every=self.progress_every,
                partial_output_every=self.partial_output_every,
                slow_file_warn_sec=self.slow_file_warn_sec,
                per_file_timeout_sec=self.per_file_timeout_sec,
                throttle_sec=self.throttle_sec,
                strict=self.strict,
                scan_session_manifest_path=self.scan_session_manifest_path,
                current_outputs=tuple(self.outputs),
                current_workers=tuple((idx, proc, output, tuple(cmd)) for idx, proc, output, cmd in self.workers),
            ),
            ProcessQueueWorkerPoolDependencies(
                subprocess_stdin=self.subprocess_stdin,
                windows_creationflags=self.windows_creationflags,
                log_error=self.log_error,
                recoverable_exceptions=self.recoverable_exceptions,
            ),
        )
        self.outputs = _copy_exact_outputs(pool_output.outputs)
        self.workers = _copy_exact_workers(pool_output.workers)
        return monitor_bool(pool_output.success, default=False, reason="process_queue_worker_pool_success_rejected")

    def replace_active_workers(self, active_workers: tuple[tuple[int, object, Path, tuple[str, ...]], ...]) -> None:
        """Replace worker state with an immutable active-worker snapshot."""

        self.workers = _copy_exact_workers(active_workers)

    def workers_tuple(self) -> tuple[tuple[int, object, Path, tuple[str, ...]], ...]:
        """Return an immutable worker snapshot for downstream scheduler owners."""

        return tuple((idx, proc, output, tuple(cmd)) for idx, proc, output, cmd in self.workers)

    def outputs_tuple(self) -> tuple[Path, ...]:
        """Return an immutable output snapshot for downstream scheduler owners."""

        return tuple(self.outputs)
