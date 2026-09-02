"""Direct in-memory parent setup recovery ownership."""
from __future__ import annotations

import logging
import time

from Virus_Scan.core.cache import bulk_scan_maintenance
from Virus_Scan.core.logging import log_bulk_progress
from Virus_Scan.scheduler.internal.live_worker_config import freeze_inmemory_worker_config
from Virus_Scan.routing.context_identity import RoutingEvidenceContext, attach_routing_evidence_to_record
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.publication.api import write_partial_scan_results
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scheduler.evidence.inmemory_final_results import InMemoryFinalPublicationRequest, publish_inmemory_parent_final_results
from Virus_Scan.scheduler.evidence.inmemory_partial_results import publish_inmemory_partial_results_from_request
from Virus_Scan.scheduler.evidence.partial_checkpoint_cache import PartialCheckpointCache
from Virus_Scan.scheduler.timeout.longtask_controller import FileScanTimeoutError
from Virus_Scan.scheduler.timeout.timeout_budget import annotate_timeout_result, compute_timeout_budget
from Virus_Scan.scheduler.workers.inmemory_file_scan import execute_inmemory_scan_one_file



def _mark_process_setup_recovery(
    path: object,
    result: object,
    *,
    per_file_timeout_sec: object,
    recovery_reason: str,
) -> object:
    if type(result) is not dict:
        return result
    evidence = dict.get(result, "timeout_evidence")
    if type(evidence) is dict:
        evidence["scheduler_mode"] = "process-setup-recovery"
        evidence["worker_state"] = "queue_worker_alive"
        evidence["timeout_reason"] = recovery_reason
        return result
    budget = compute_timeout_budget(
        path,
        configured_timeout_seconds=per_file_timeout_sec,
        workload_class=dict.get(result, "effective_stage"),
        method="process",
    )
    annotated = annotate_timeout_result(
        result,
        budget,
        worker_state="queue_worker_alive",
        reason=recovery_reason,
    )
    timeout_evidence = dict.get(annotated, "timeout_evidence")
    if type(timeout_evidence) is dict:
        timeout_evidence["scheduler_mode"] = "process-setup-recovery"
    return annotated


def run_direct_process_setup_recovery(
    *,
    all_files: object,
    total_files: int,
    started_at: float,
    strict: bool,
    yara_enabled: bool,
    progress_every: int,
    throttle_sec: float,
    partial_output_path: object,
    partial_output_every: int,
    slow_file_warn_sec: object,
    per_file_timeout_sec: object,
    recoverable_exceptions: tuple[type[BaseException], ...],
    recovery_reason: str,
    root: object = None,
    result_retainer: object = None,
    derived_cache_writer: object = None,
) -> dict[object, object]:
    logging.warning(
        "bulk scan scheduler=inmemory recovery_reason=%s; "
        "using process-owned serial recovery without IPC transport",
        recovery_reason,
    )
    results: dict[object, object] = {}
    partial_checkpoint_cache = PartialCheckpointCache()
    routing_root = root if root is not None else None
    routing_context = RoutingEvidenceContext.build(routing_root) if routing_root is not None else None
    for index, path in enumerate(tuple(all_files)):
        cfg = freeze_inmemory_worker_config(
            {
                "prev_stage": "unknown",
                "routing_evidence_context": routing_context,
                "strict": strict,
                "yara_enabled": yara_enabled,
                "per_file_timeout_sec": per_file_timeout_sec,
                "slow_file_warn_sec": slow_file_warn_sec,
                "timeout_budget_factory": compute_timeout_budget,
                "timeout_result_annotator": annotate_timeout_result,
                "timeout_error_type": FileScanTimeoutError,
            }
        )
        completed_path, result = execute_inmemory_scan_one_file(path, cfg)
        result = _mark_process_setup_recovery(
            completed_path,
            result,
            per_file_timeout_sec=per_file_timeout_sec,
            recovery_reason=recovery_reason,
        )
        if type(result) is dict and routing_root is not None:
            result = attach_routing_evidence_to_record(
                result,
                completed_path,
                container_root=routing_root,
                evidence_context=routing_context,
            )
        if not callable(result_retainer):
            raise TypeError("process_setup_recovery_result_retainer_required")
        if not callable(derived_cache_writer):
            raise TypeError("process_setup_recovery_derived_cache_writer_required")
        results[completed_path] = result_retainer(completed_path, result)
        derived_cache_writer(result)
        bulk_scan_maintenance(index + 1)
        log_bulk_progress(index + 1, total_files, file_path=completed_path, started_at=started_at, progress_every=progress_every)
        throttle_value, throttle_reason = scheduler_float(
            throttle_sec,
            default=0.0,
            minimum=0.0,
            reason="process_setup_recovery_throttle_rejected",
        )
        if throttle_reason == "" and throttle_value:
            time.sleep(throttle_value)
    publish_inmemory_parent_final_results(InMemoryFinalPublicationRequest(
        partial_output_path=partial_output_path, results=results,
        partial_output_every=partial_output_every, writer=write_partial_scan_results,
        checkpoint_cache=partial_checkpoint_cache, log_error=log_error,
        publish_partial_results=publish_inmemory_partial_results_from_request,
        recoverable_exceptions=recoverable_exceptions,
    ))
    return results


__all__ = ("run_direct_process_setup_recovery",)
