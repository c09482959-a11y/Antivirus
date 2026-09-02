"""In-memory single-file scan execution owner.

This module owns the picklable long-lived worker file scan path.  It is split
from scan_job_executor so public single-file scheduler execution and in-memory
worker execution no longer share one oversized execution module.
"""
from __future__ import annotations

from Virus_Scan.runtime.api import clear_progress_callback, log_error, record_scheduler_suppressed
from Virus_Scan.runtime.api import set_progress_callback
from Virus_Scan.scheduler.workers.heartbeat import UmigeCooperativeCancel
from Virus_Scan.scheduler.workers.inmemory_file_scan_support import cfg_value, owned_cfg_snapshot
from Virus_Scan.scheduler.workers.inmemory_raw_scan import scan_file_inmemory_raw
from Virus_Scan.scheduler.workers.inmemory_scan_progress import InMemoryScanProgressEmitter
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result
from Virus_Scan.scheduler.workers.inmemory_file_scan_steps import (
    build_cancel_result,
    build_inmemory_scan_context,
    build_timeout_result,
    build_worker_failure_result,
    execute_inmemory_scan_context,
)
from Virus_Scan.scheduler.workers.thread_progress import (
    clear_thread_progress_callback,
    set_thread_progress_callback,
)


INMEMORY_SCHEDULER_EXCEPTIONS = (OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError)


def execute_inmemory_scan_one_file(path: object, cfg: object = None) -> object:
    cfg = owned_cfg_snapshot(cfg)
    timeout_budget_factory = cfg_value(cfg, 'timeout_budget_factory') if cfg is not None else None
    timeout_result_annotator = cfg_value(cfg, 'timeout_result_annotator') if cfg is not None else None
    timeout_error_type = cfg_value(cfg, 'timeout_error_type') if cfg is not None else None
    setup = build_inmemory_scan_context(
        path=path,
        cfg=cfg,
        timeout_budget_factory=timeout_budget_factory,
        timeout_result_annotator=timeout_result_annotator,
        timeout_error_type=timeout_error_type,
        recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        record_suppressed=record_scheduler_suppressed,
    )
    if setup.context is None:
        return setup.early_result
    context = setup.context
    set_thread_progress_callback(
        context.progress,
        set_progress_callback=set_progress_callback,
        record_suppressed=record_scheduler_suppressed,
    )
    try:
        return execute_inmemory_scan_context(
            context=context,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        )
    except UmigeCooperativeCancel as exc:
        return build_cancel_result(path, exc)
    except context.timeout_error_type as exc:
        if context.strict:
            raise
        return build_timeout_result(context, exc)
    except INMEMORY_SCHEDULER_EXCEPTIONS as exc:
        if context.strict:
            raise
        return build_worker_failure_result(
            context=context,
            error=exc,
            log_error=log_error,
            record_suppressed=record_scheduler_suppressed,
            recoverable_exceptions=INMEMORY_SCHEDULER_EXCEPTIONS,
        )
    finally:
        clear_thread_progress_callback(
            clear_progress_callback=clear_progress_callback,
            record_suppressed=record_scheduler_suppressed,
        )


__all__ = (
    "InMemoryScanProgressEmitter",
    "cfg_value",
    "execute_inmemory_scan_one_file",
    "make_scheduler_worker_error_result",
    "owned_cfg_snapshot",
    "scan_file_inmemory_raw",
)
