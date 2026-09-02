"""Process-queue startup orchestration ownership."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from Virus_Scan.contracts.scan_session_snapshot import ScanSessionSnapshot
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_float,
    scheduler_int,
    scheduler_path_text,
)

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS as RAW_QUEUE_RECOVERABLE_EXCEPTIONS
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping
from Virus_Scan.scheduler.runtime.scan_session_manifest import publish_scan_session_manifest
from Virus_Scan.scheduler.queue.authority import ensure_process_queue_dirs
from Virus_Scan.scheduler.ownership.scheduler_identity import build_scheduler_process_identity
from Virus_Scan.scheduler.orchestration.process_queue_startup_admission import (
    ProcessQueueStartupAdmissionRequest,
    prepare_process_queue_startup_admission,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup_capacity import build_process_queue_startup_capacity
from Virus_Scan.scheduler.orchestration.process_queue_startup_integrity import (
    ProcessQueueStartupIntegrityRequest,
    repair_process_queue_startup_integrity,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup_worker_pool import build_process_queue_startup_worker_pool
from Virus_Scan.scheduler.orchestration.process_queue_startup_workers import (
    ProcessQueueStartupWorkerRequest,
    publish_process_queue_startup_workers,
)
from Virus_Scan.scheduler.orchestration.process_queue_startup_state import ProcessQueueStartupState
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from pathlib import Path

@dataclass(frozen=True)
class ProcessQueueStartupRequest:
    """Immutable input for process-queue startup orchestration."""

    root: str | Path
    all_files: tuple[str, ...]
    process_count: int
    strict: bool
    progress_every: int
    throttle_sec: float
    partial_output_every: int
    slow_file_warn_sec: float
    per_file_timeout_sec: float
    scan_session_snapshot: ScanSessionSnapshot

    def __post_init__(self) -> None:
        if type(self.scan_session_snapshot) is not ScanSessionSnapshot:
            raise TypeError("process_queue_startup_scan_session_snapshot_required")
        if type(self.all_files) not in {list, tuple}:
            raise ValueError("process_queue_startup_all_files_rejected")
        files: list[str] = []
        for path in self.all_files:
            path_text, path_reason = scheduler_path_text(path)
            if path_reason or not path_text:
                reason = path_reason or "missing_path"
                raise ValueError("process_queue_startup_file_rejected:" + reason)
            files.append(path_text)
        process_count, process_reason = scheduler_int(
            self.process_count,
            minimum=1,
            reason="process_queue_startup_process_count_rejected",
        )
        strict, strict_reason = scheduler_bool(
            self.strict,
            reason="process_queue_startup_strict_rejected",
        )
        progress_every, progress_reason = scheduler_int(
            self.progress_every,
            minimum=1,
            reason="process_queue_startup_progress_every_rejected",
        )
        throttle_sec, throttle_reason = scheduler_float(
            self.throttle_sec,
            minimum=0.0,
            reason="process_queue_startup_throttle_rejected",
        )
        partial_output_every, partial_reason = scheduler_int(
            self.partial_output_every,
            minimum=0,
            reason="process_queue_startup_partial_every_rejected",
        )
        slow_file_warn_sec, slow_reason = scheduler_float(
            self.slow_file_warn_sec,
            minimum=0.0,
            reason="process_queue_startup_slow_warn_rejected",
        )
        per_file_timeout_sec, timeout_reason = scheduler_float(
            self.per_file_timeout_sec,
            minimum=0.0,
            reason="process_queue_startup_timeout_rejected",
        )
        reasons = tuple(
            reason
            for reason in (
                process_reason,
                strict_reason,
                progress_reason,
                throttle_reason,
                partial_reason,
                slow_reason,
                timeout_reason,
            )
            if reason
        )
        if reasons:
            raise ValueError(",".join(reasons))
        object.__setattr__(self, "all_files", tuple(files))
        object.__setattr__(self, "process_count", process_count)
        object.__setattr__(self, "strict", strict)
        object.__setattr__(self, "progress_every", progress_every)
        object.__setattr__(self, "throttle_sec", throttle_sec)
        object.__setattr__(self, "partial_output_every", partial_output_every)
        object.__setattr__(self, "slow_file_warn_sec", slow_file_warn_sec)
        object.__setattr__(self, "per_file_timeout_sec", per_file_timeout_sec)


def start_process_queue(request: ProcessQueueStartupRequest) -> ProcessQueueStartupState:
    """Start process-queue runtime resources and publish initial workers."""

    scheduler_identity = build_scheduler_process_identity()
    capacity = build_process_queue_startup_capacity(
        all_files=tuple(request.all_files),
        requested_process_count=request.process_count,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
    )
    scan_session_manifest = publish_scan_session_manifest(
        capacity.runtime_dirs.run_dir, request.scan_session_snapshot)
    admission = prepare_process_queue_startup_admission(
        ProcessQueueStartupAdmissionRequest(
            queue_dir=capacity.queue_dir,
            all_files=tuple(request.all_files),
            process_count=capacity.process_count,
            requested_process_count=capacity.requested_process_count,
            dynamic_queue_feed=capacity.dynamic_queue_feed,
        )
    )
    repair_process_queue_startup_integrity(
        ProcessQueueStartupIntegrityRequest(queue_dir=capacity.queue_dir, all_files=tuple(request.all_files))
    )
    worker_pool = build_process_queue_startup_worker_pool(
        root=request.root,
        queue_dir=capacity.queue_dir,
        outputs_dir=capacity.outputs_dir,
        scheduler_identity=scheduler_identity,
        dynamic_queue_feed=capacity.dynamic_queue_feed,
        progress_every=request.progress_every,
        partial_output_every=request.partial_output_every,
        slow_file_warn_sec=request.slow_file_warn_sec,
        per_file_timeout_sec=request.per_file_timeout_sec,
        throttle_sec=request.throttle_sec,
        strict=request.strict,
        recoverable_exceptions=RAW_QUEUE_RECOVERABLE_EXCEPTIONS,
        scan_session_manifest_path=scan_session_manifest,
    )
    workers = publish_process_queue_startup_workers(
        ProcessQueueStartupWorkerRequest(
            queue_dir=capacity.queue_dir,
            worker_pool=worker_pool,
            process_count=capacity.process_count,
            requested_process_count=capacity.requested_process_count,
        )
    )
    logging.info(
        "bulk scan scheduler=process-queue processes_max=%s requested=%s "
        "files=%s cap=%s; elastic=%s; dynamic work-stealing + "
        "CPU-fill oversubscribe enabled",
        int.__str__(capacity.process_count),
        int.__str__(capacity.requested_process_count),
        int.__str__(len(request.all_files)),
        int.__str__(capacity.process_capacity.cpu_fill_cap),
        "on" if workers.elastic_scheduler else "off",
    )
    ensure_process_queue_dirs(capacity.queue_dir)
    return ProcessQueueStartupState(
        queue_dir=capacity.queue_dir,
        outputs_dir=capacity.outputs_dir,
        runtime_dir=capacity.runtime_dirs.run_dir,
        worker_pool=worker_pool,
        ordered_queue_items=admission.ordered_queue_items,
        queue_feed_cursor=admission.queue_feed_cursor,
        queue_enqueued_identities=admission.queue_enqueued_identities,
        queue_total_enqueued=admission.queue_total_enqueued,
        queue_last_feed_log=0.0,
        raw_stage_progress_state=immutable_mapping(),
        process_count=capacity.process_count,
        requested_process_count=capacity.requested_process_count,
        dynamic_queue_feed=capacity.dynamic_queue_feed,
        elastic_scheduler=workers.elastic_scheduler,
        elastic_min_workers=workers.elastic_min_workers,
        next_worker_spawn_id=workers.next_worker_spawn_id,
    )
