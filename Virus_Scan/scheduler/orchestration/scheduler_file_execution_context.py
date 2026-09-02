"""Scheduler file-execution dependency context ownership."""
from __future__ import annotations

import logging
import os
import threading
import time
from contextlib import nullcontext
from typing import cast

from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.result_record import make_terminal_asset_result, make_timeout_result
from Virus_Scan.core.logging import get_detector_errors
from Virus_Scan.detection.api.public_contracts import contextual_dangerous_anchor_hits
from Virus_Scan.detection.api.runner import analyze_file_full_observe_only
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.routing.context_identity import attach_routing_evidence_to_record
from Virus_Scan.routing.extension_scan_router import scan_file_by_type
from Virus_Scan.runtime.api import log_error
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.execution.scheduler_file_job import SchedulerFileExecutionDependencies
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_worker_error_result
from Virus_Scan.scheduler.execution.triage_escalation import should_escalate_after_triage
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_path_text
from Virus_Scan.scheduler.runtime.deep_scan_policy import scheduler_deep_scan_thorough
from Virus_Scan.scheduler.runtime.passive_asset_triage import is_terminal_clean_asset_triage
from Virus_Scan.scheduler.timeout.longtask_controller import FileScanTimeoutError, per_file_timeout
from Virus_Scan.scheduler.timeout.timeout_budget import TimeoutBudget, annotate_timeout_result, compute_timeout_budget
from Virus_Scan.utils.stages import effective_stage_for_path
from Virus_Scan.utils.tagging import normalize_tags
from Virus_Scan.yara.match import normalize_yara_hits, yara_scan_with_optional_zip


def build_scheduler_file_execution_dependencies() -> SchedulerFileExecutionDependencies:
    """Build explicit dependencies for one-file scheduler execution."""

    def per_file_timeout_context(seconds: float) -> object:
        safe_seconds, _reason = scheduler_int(
            seconds,
            default=0,
            minimum=0,
            reason="scheduler_file_timeout_seconds_rejected",
        )
        return per_file_timeout(safe_seconds)

    def scheduler_timeout_budget(
        path: object,
        *,
        configured_timeout_seconds: float | None = None,
        workload_class: str | None = None,
        method: str | None = None,
        tags: object = None,
        deep_scan: bool = False,
        recursion_depth: int = 0,
        file_size_probe: object = None,
        artifact_read_snapshot: object = None,
    ) -> TimeoutBudget:
        safe_path = path if isinstance(path, (str, os.PathLike)) else None
        return compute_timeout_budget(
            cast("str | os.PathLike[str] | None", safe_path),
            configured_timeout_seconds=configured_timeout_seconds,
            workload_class=workload_class,
            method=method,
            tags=tags,
            deep_scan=deep_scan,
            recursion_depth=recursion_depth,
            file_size_probe=file_size_probe,
            artifact_read_snapshot=artifact_read_snapshot,
        )

    return SchedulerFileExecutionDependencies(
        current_thread=threading.current_thread,
        main_thread=threading.main_thread,
        nullcontext_factory=nullcontext,
        per_file_timeout=per_file_timeout_context,
        compute_timeout_budget=scheduler_timeout_budget,
        scan_file_by_type=scan_file_by_type,
        effective_stage_for_path=effective_stage_for_path,
        normalize_tags=normalize_tags,
        terminal_asset_triage=is_terminal_clean_asset_triage,
        make_terminal_asset_result=make_terminal_asset_result,
        attach_routing_evidence_to_record=attach_routing_evidence_to_record,
        should_escalate_after_triage=should_escalate_after_triage,
        get_scan_extension=get_scan_extension,
        deep_scan_thorough=scheduler_deep_scan_thorough,
        contextual_dangerous_anchor_hits=contextual_dangerous_anchor_hits,
        record_runtime_suppressed=lambda label, exc: record_suppressed_failure(label, exc, domain="runtime"),
        normalize_yara_hits=normalize_yara_hits,
        yara_scan_with_optional_zip=yara_scan_with_optional_zip,
        analyze_file_full_observe_only=analyze_file_full_observe_only,
        get_detector_errors=get_detector_errors,
        make_timeout_result=make_timeout_result,
        annotate_timeout_result=annotate_timeout_result,
        make_worker_error_result=make_scheduler_worker_error_result,
        log_error=log_error,
        time=time.time,
        basename=lambda path: os.path.basename(scheduler_path_text(path)[0]),
        warn_slow_file=logging.warning,
        recoverable_exceptions=RECOVERABLE_RUNTIME_ERRORS,
        timeout_exception_type=FileScanTimeoutError,
    )
