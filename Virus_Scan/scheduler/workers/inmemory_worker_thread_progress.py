from Virus_Scan.contracts.env_config import float_env
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool, scheduler_float, scheduler_int
from Virus_Scan.scheduler.workers.inmemory_scan_progress import _exception_type_tuple
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import (
    safe_lifecycle_text,
    worker_lifecycle_exception_reason,
)
from dataclasses import dataclass
import time
from typing import Callable, Optional

_THREAD_PROGRESS_STAGE_TEXT, _THREAD_PROGRESS_INC_MINIMUM, _THREAD_PROGRESS_RSS_LIMIT_MB = "scan", 1, 2048.0


def _record_task_meta_rejection(task_meta: object, reason: str) -> None:
    if type(task_meta) is dict and type(reason) is str and reason:
        prior = dict.get(task_meta, "thread_progress_input_rejections")
        task_meta["thread_progress_input_rejections"] = (*prior, reason) if type(prior) is tuple else (reason,)

from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress_evidence import WorkerThreadProgressHeartbeatEvidence
from Virus_Scan.scheduler.workers.inmemory_worker_thread_progress_publication import publish_shared_worker_thread_heartbeat



@dataclass
class InMemoryWorkerThreadProgress:
    """Timeout-owned per-job heartbeat/progress state for one in-memory worker thread.

    The object is context-owned by a single worker job. It does not publish mutable
    scheduler dictionaries across areas; updates are emitted through the supplied
    heartbeat writer and optional task metadata owned by the worker execution context.
    Heartbeat publication failures are reported as immutable worker-owned evidence
    instead of being treated as clean progress.
    """

    cfg: dict
    job_id: str
    generation: int
    cancel_table: object
    heartbeat_table: object
    heartbeat_flags: object
    completed_jobs: int
    task_meta: Optional[dict]
    cancel_requested: Callable[[object, str, int], bool]
    update_shared_heartbeat: Callable[..., object]
    record_heartbeat_failure: Optional[Callable[[str, BaseException], object]] = None
    recoverable_exceptions: tuple[type[BaseException], ...] = (Exception,)

    progress_counter: int = 0
    bytes_processed: int = 0
    last_progress_ns: int = 0
    stage_started_ns: int = 0
    heartbeat_failure_count: int = 0
    last_heartbeat_failure: Optional[dict[str, object]] = None

    def __post_init__(self) -> object:
        self.cfg = dict(self.cfg) if type(self.cfg) is dict else {}
        self.recoverable_exceptions = _exception_type_tuple(self.recoverable_exceptions)
        now = time.monotonic_ns()
        self.last_progress_ns = int(now)
        self.stage_started_ns = int(now)



    def _worker_rss_limit(self) -> float:
        rss_limit_source = dict.get(self.cfg, "worker_rss_limit_mb") if type(self.cfg) is dict else None
        if rss_limit_source is None:
            rss_limit_source = float_env("UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB", _THREAD_PROGRESS_RSS_LIMIT_MB, 0.0, None)
        rss_limit, rss_reason = scheduler_float(
            rss_limit_source,
            minimum=0.0,
            reason="worker_thread_progress_rss_limit_rejected",
            non_finite_reason="non_finite_worker_thread_progress_rss_limit",
        )
        if not rss_reason:
            return rss_limit
        _record_task_meta_rejection(self.task_meta, rss_reason)
        return _THREAD_PROGRESS_RSS_LIMIT_MB




    def _record_heartbeat_failure(self, *, stage_name: str, reason: str, exc: BaseException | None = None) -> None:
        job_text, job_reason = safe_lifecycle_text(self.job_id, replacement_text="worker", missing_reason="missing_worker_thread_progress_job_id", unsupported_reason="unsupported_worker_thread_progress_job_id")
        stage_text, stage_reason = safe_lifecycle_text(stage_name, replacement_text=_THREAD_PROGRESS_STAGE_TEXT, missing_reason="missing_worker_thread_progress_stage", unsupported_reason="unsupported_worker_thread_progress_stage")
        reason_text, reason_unavailable = safe_lifecycle_text(reason, replacement_text="shared heartbeat publication failed", missing_reason="missing_worker_thread_progress_reason", unsupported_reason="unsupported_worker_thread_progress_reason")
        attempt, attempt_reason = scheduler_int(self.generation, minimum=0, reason="worker_thread_progress_generation_rejected")
        progress_counter, counter_reason = scheduler_int(self.progress_counter, minimum=0, reason="worker_thread_progress_counter_rejected")
        for rejection in (job_reason, stage_reason, reason_unavailable, attempt_reason, counter_reason):
            _record_task_meta_rejection(self.task_meta, rejection)
        evidence = WorkerThreadProgressHeartbeatEvidence(
            job_id=job_text,
            attempt=attempt,
            stage=stage_text,
            progress_counter=progress_counter,
            reason=reason_text,
        )
        evidence_metadata = dict(evidence.as_metadata())
        self.heartbeat_failure_count += 1
        self.last_heartbeat_failure = evidence_metadata
        if type(self.task_meta) is dict:
            self.task_meta["thread_progress_heartbeat_publish_failed"] = True
            self.task_meta["thread_progress_heartbeat_evidence"] = evidence_metadata
        if self.record_heartbeat_failure is None:
            return
        try:
            failure = exc if exc is not None else RuntimeError("worker_thread_progress_heartbeat_failed")
            self.record_heartbeat_failure("worker_thread_progress_heartbeat_failed", failure)
        except _exception_type_tuple(self.recoverable_exceptions) as recorder_exc:
            _record_task_meta_rejection(self.task_meta, worker_lifecycle_exception_reason(recorder_exc))

    def __call__(self, stage: object='scan', inc: object=1, bytes_delta: object=0) -> object:
        stage_name, stage_reason = safe_lifecycle_text(
            stage,
            replacement_text=_THREAD_PROGRESS_STAGE_TEXT,
            missing_reason='missing_worker_thread_progress_stage',
            unsupported_reason='unsupported_worker_thread_progress_stage',
        )
        inc_raw, inc_reason = scheduler_int(
            inc,
            minimum=_THREAD_PROGRESS_INC_MINIMUM,
            reason="worker_thread_progress_increment_rejected",
        )
        bytes_raw, bytes_reason = scheduler_int(
            bytes_delta,
            minimum=0,
            reason="worker_thread_progress_bytes_delta_rejected",
        )
        for rejection in (stage_reason, inc_reason, bytes_reason):
            _record_task_meta_rejection(self.task_meta, rejection)

        inc_value = max(1, inc_raw)
        bytes_value = max(0, bytes_raw)
        self.progress_counter += inc_value
        self.bytes_processed += bytes_value
        now = time.monotonic_ns()
        self.last_progress_ns = int(now)
        self.stage_started_ns = int(now)
        if type(self.task_meta) is dict:
            self.task_meta['stage'] = stage_name
            self.task_meta['progress_counter'] = int(self.progress_counter)
            self.task_meta['bytes_processed'] = int(self.bytes_processed)
            self.task_meta['last_progress_ns'] = int(self.last_progress_ns)
            self.task_meta['stage_started_ns'] = int(self.stage_started_ns)

        rss_mb, rss_limit = 0.0, self._worker_rss_limit()

        flags = int(self.heartbeat_flags.running)
        cancelled_raw = self.cancel_requested(self.cancel_table, self.job_id, self.generation)
        cancelled, cancel_reason = scheduler_bool(
            cancelled_raw,
            reason="worker_thread_progress_cancel_flag_rejected",
        )
        _record_task_meta_rejection(self.task_meta, cancel_reason)
        if cancelled:
            flags |= int(self.heartbeat_flags.cancel_request)
        if rss_limit > 0 and rss_mb > rss_limit:
            flags |= self.heartbeat_flags.poisoned_or_retire_mask
            if type(self.task_meta) is dict:
                self.task_meta['poisoned_rss_mb'] = float(rss_mb)

        heartbeat_published, heartbeat_failure_recorded = publish_shared_worker_thread_heartbeat(
            self,
            stage_name=stage_name,
            flags=flags,
            rss_mb=rss_mb,
            record_task_meta_rejection=_record_task_meta_rejection,
            record_heartbeat_failure=self._record_heartbeat_failure,
        )
        if not heartbeat_published and not heartbeat_failure_recorded:
            self._record_heartbeat_failure(
                stage_name=stage_name,
                reason="shared heartbeat update returned false",
            )
        if cancelled or (rss_limit > 0 and rss_mb > rss_limit):
            return False
        return True
__all__ = ("InMemoryWorkerThreadProgress", "WorkerThreadProgressHeartbeatEvidence")
