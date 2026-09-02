"""Process scheduler setup recovery helpers."""
from __future__ import annotations

import logging

_LOGGER = logging.getLogger(__name__)
import time
from typing import Callable

from Virus_Scan.core.cache import bulk_scan_maintenance
from Virus_Scan.core.logging import log_bulk_progress
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.orchestration.scheduler_serial_mode import (
    SchedulerSerialModeDependencies,
    SchedulerSerialModeRequest,
    run_scheduler_serial_mode,
)
from Virus_Scan.scheduler.timeout.timeout_budget import annotate_timeout_result, compute_timeout_budget


def run_process_setup_recovery_serial_mode(
    request: object,
    worker: Callable[..., object],
    write_partial: Callable[..., object],
    result_retainer: Callable[[object, object], object],
    derived_cache_writer: Callable[[object], object],
) -> dict[object, object]:
    _LOGGER.warning(
        "bulk scan scheduler=process setup unavailable; "
        "using process-owned serial recovery without threaded transport"
    )
    def prepare_recovered_result(path: object, result: object) -> object:
        result_data = materialize_scheduler_mapping(result)
        if type(result_data) is not dict:
            return result_retainer(path, result)
        budget = compute_timeout_budget(
            path,
            configured_timeout_seconds=request.per_file_timeout_sec,
            workload_class=dict.get(result_data, "effective_stage"),
            method="process",
        )
        annotated = annotate_timeout_result(
            result_data,
            budget,
            worker_state="queue_worker_alive",
            reason="process_scheduler_setup_recovered",
        )
        evidence = dict.get(annotated, "timeout_evidence")
        if type(evidence) is dict:
            evidence["scheduler_mode"] = "process-setup-recovery"
        return result_retainer(path, annotated)

    serial_result = run_scheduler_serial_mode(
        SchedulerSerialModeRequest(
            files=request.all_files,
            total_files=request.total_files,
            started_at=request.scan_started_at,
            progress_every=request.progress_every,
            throttle_sec=request.throttle_sec,
            results={},
        ),
        SchedulerSerialModeDependencies(
            worker=worker,
            prepare_result=prepare_recovered_result,
            write_derived_cache=derived_cache_writer,
            write_partial=write_partial,
            bulk_scan_maintenance=bulk_scan_maintenance,
            log_bulk_progress=log_bulk_progress,
            sleep=time.sleep,
        ),
    )
    materialized = materialize_scheduler_mapping(serial_result.results)
    if type(materialized) is dict:
        return materialized
    return dict(serial_result.results)


__all__ = ("run_process_setup_recovery_serial_mode",)
