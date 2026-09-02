"""Worker-owned process-queue spawn policy and lifecycle publication.

This module owns deterministic process-child command construction and launch.
Execution/orchestration callers receive immutable publication data and do not
own subprocess command construction or worker spawn semantics.
"""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple, materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_error_detail, scheduler_path_text
from Virus_Scan.scheduler.workers.spawn_command_support import _build_process_queue_worker_command_with_evidence

_PATH_TYPE = type(Path("."))

@dataclass(frozen=True)
class ProcessQueueWorkerSpawnRequest:
    root: object
    queue_dir: object
    output: object
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
        object.__setattr__(self, "env_base", immutable_mapping(self.env_base))
        if type(self.scan_session_manifest_path) is not _PATH_TYPE:
            raise TypeError("process_queue_worker_manifest_path_required")


@dataclass(frozen=True)
class ProcessQueueWorkerSpawnResult:
    success: bool
    worker_index: int
    output: Path
    command: tuple[str, ...]
    process: object = None
    error: str = ""
    evidence: object = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", immutable_tuple(self.command))
        object.__setattr__(self, "evidence", immutable_mapping(self.evidence) if self.evidence is not None else immutable_mapping())



def build_process_queue_worker_command(request: ProcessQueueWorkerSpawnRequest) -> tuple[str, ...]:
    """Build the deterministic queue-child command for standalone/onefile and source runs."""
    command, _rejections = _build_process_queue_worker_command_with_evidence(request)
    return command


def spawn_process_queue_worker(
    request: ProcessQueueWorkerSpawnRequest,
    *,
    subprocess_stdin: Callable[[], object],
    windows_creationflags: Callable[..., int],
    log_error: Callable[[str], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> ProcessQueueWorkerSpawnResult:
    """Launch one queue child and return immutable lifecycle publication data."""
    command, rejections = _build_process_queue_worker_command_with_evidence(request)
    output_text, output_reason = scheduler_path_text(request.output)
    output_path = Path(output_text if output_reason == "" and output_text else "scheduler_worker_spawn_output_rejected.json")
    script_text, script_reason = scheduler_path_text(request.script_path)
    cwd = Path(script_text).parent if script_reason == "" and script_text else Path.cwd()
    if rejections:
        evidence = {
            "scheduler_worker_spawn_rejected": True,
            "rejections": tuple(rejections),
            "command": command,
        }
        log_error("process queue worker launch rejected before subprocess: " + json.dumps(materialize_scheduler_mapping(evidence), sort_keys=True, separators=(",", ":")))
        if request.strict is True:
            exception_message = "process queue worker spawn input rejected without caller hooks"
            raise RuntimeError(exception_message)
        return ProcessQueueWorkerSpawnResult(success=False, worker_index=request.worker_index, output=output_path, command=command, error="scheduler_worker_spawn_input_rejected", evidence=evidence)
    try:
        proc = subprocess.Popen(  # noqa: S603
            list(command),
            env=dict(request.env_base),
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess_stdin(),
            text=True,
            errors="replace",
            creationflags=windows_creationflags(worker=True),
            start_new_session=(os.name != "nt"),
        )
        return ProcessQueueWorkerSpawnResult(success=True, worker_index=request.worker_index, output=output_path, command=command, process=proc)
    except FileNotFoundError as exc:
        detail = scheduler_error_detail(exc)
        log_error(
            "process queue worker launch failed: "
            + detail
            + "; python_exe=" + command[0]
            + "; script_path=" + (command[1] if len(command) > 1 else "<frozen>")
        )
        if request.strict is True:
            raise
        return ProcessQueueWorkerSpawnResult(success=False, worker_index=request.worker_index, output=output_path, command=command, error=detail)
    except recoverable_exceptions as exc:
        detail = scheduler_error_detail(exc)
        log_error("process queue worker launch failed unexpectedly: " + detail)
        if request.strict is True:
            raise
        return ProcessQueueWorkerSpawnResult(success=False, worker_index=request.worker_index, output=output_path, command=command, error=detail)


@dataclass(frozen=True)
class ProcessQueueWorkerRecord:
    worker_index: int
    process: object
    output: Path
    command: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "command", immutable_tuple(self.command))


@dataclass(frozen=True)
class ProcessQueueSpawnPublication:
    success: bool
    output: Path
    active_worker: ProcessQueueWorkerRecord | None


def spawn_and_publish_process_queue_worker(
    request: ProcessQueueWorkerSpawnRequest,
    *,
    subprocess_stdin: Callable[[], object],
    windows_creationflags: Callable[..., int],
    log_error: Callable[[str], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> ProcessQueueSpawnPublication:
    """Launch one queue child and publish immutable worker lifecycle output.

    The execution phase owns worker-process creation and the shape of the
    lifecycle record.  The process-queue runner stores only the immutable publication returned here;
    it does not carry nested spawn helpers or process lifecycle semantics inside
    orchestration state.
    """
    result = spawn_process_queue_worker(
        request,
        subprocess_stdin=subprocess_stdin,
        windows_creationflags=windows_creationflags,
        log_error=log_error,
        recoverable_exceptions=recoverable_exceptions,
    )
    if not result.success:
        return ProcessQueueSpawnPublication(success=False, output=result.output, active_worker=None)
    return ProcessQueueSpawnPublication(
        success=True,
        output=result.output,
        active_worker=ProcessQueueWorkerRecord(
            worker_index=result.worker_index,
            process=result.process,
            output=result.output,
            command=result.command,
        ),
    )
