"""Bounded execution and failure-publication steps for in-memory scans."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.scan_session_snapshot import attach_scan_session_record
from Virus_Scan.scheduler.execution.scheduler_file_job_types import SchedulerFileExecutionRequest
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_exception_text
from Virus_Scan.scheduler.orchestration.scheduler_file_execution_context import (
    build_scheduler_file_execution_dependencies,
)
from Virus_Scan.scheduler.execution.scheduler_file_cache import (
    execute_scheduler_file_with_cache,
)
from Virus_Scan.scheduler.workers.inmemory_file_scan_context import (
    InMemoryScanContext,
    InMemoryScanSetup,
    build_inmemory_scan_context,
)
from Virus_Scan.scheduler.workers.inmemory_file_scan_support import (
    build_inmemory_timeout_result,
    report_inmemory_worker_failure,
)
from Virus_Scan.scheduler.workers.result_contracts import (
    make_scheduler_cancel_result,
    make_scheduler_worker_error_result,
)


def execute_inmemory_scan_context(
    *,
    context: InMemoryScanContext,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> object:
    """Run process-transport work through the canonical scheduler file owner."""
    compiled_rules = context.compiled_rules if context.yara_enabled else None
    context.progress("start")
    context.progress("analyze_full")
    root = context.routing_evidence_context.container_root
    completed = execute_scheduler_file_with_cache(
        request=SchedulerFileExecutionRequest(
            path=context.path,
            root=root,
            previous_stage=context.prev_stage,
            compiled_rules=compiled_rules,
            per_file_timeout_sec=context.per_file_timeout_sec,
            slow_file_warn_sec=context.slow_file_warn_sec,
            strict=context.strict,
            yara_enabled=context.yara_enabled,
            use_signal_timeout=False,
            routing_evidence_context=context.routing_evidence_context,
            scan_session_snapshot=context.scan_session_snapshot,
            artifact_read_snapshot=context.artifact_read_snapshot,
        ),
        file_execution_dependencies=build_scheduler_file_execution_dependencies(),
        started_file=context.started_file,
    )
    if type(completed) is tuple and len(completed) == 2 and type(completed[1]) is dict:
        attach_scan_session_record(completed[1], context.scan_session_snapshot)
    return completed


def build_cancel_result(path: object, error: BaseException) -> object:
    return make_scheduler_cancel_result(path, scheduler_exception_text(error))


def build_timeout_result(context: InMemoryScanContext, error: BaseException) -> object:
    return build_inmemory_timeout_result(
        path=context.path,
        error=error,
        active_timeout_budget=context.active_timeout_budget,
        timeout_result_annotator=context.timeout_result_annotator,
    )


def build_worker_failure_result(
    *,
    context: InMemoryScanContext,
    error: BaseException,
    log_error: Callable[[str], object],
    record_suppressed: Callable[[str, BaseException], object],
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> object:
    report_inmemory_worker_failure(
        path=context.path,
        error=error,
        log_error=log_error,
        record_scheduler_suppressed=record_suppressed,
        recoverable_exceptions=recoverable_exceptions,
    )
    return (context.path, make_scheduler_worker_error_result(context.path, error))


__all__ = (
    "InMemoryScanContext",
    "InMemoryScanSetup",
    "build_cancel_result",
    "build_inmemory_scan_context",
    "build_timeout_result",
    "build_worker_failure_result",
    "execute_inmemory_scan_context",
)
