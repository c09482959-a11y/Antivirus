"""Helper ownership for terminal missing-file finalization."""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Iterable

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_path_text,
    scheduler_value_snapshot,
)
from Virus_Scan.scheduler.queue.terminal_accounting_evidence import (
    report_terminal_accounting_failure,
)
from Virus_Scan.scheduler.queue.terminal_accounting_support import (
    accounting_float,
    accounting_int,
    durable_results,
    path_entries,
)
from Virus_Scan.scheduler.queue.terminal_worker_cleanup import terminate_processes
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload

_TERMINAL_ACCOUNTING_EXCEPTIONS = (OSError, RuntimeError, TypeError, ValueError)
_WORKER_ERROR_RESULT_MAPPING_REJECTED = "worker error result mapping rejected"


def terminal_accounting_ready(
    *,
    feed_complete: bool,
    no_live_queue_work: bool,
    accounted_files: int,
    total_files: int,
    idle_elapsed: float,
    idle_grace_sec: float,
    report: Callable[..., object],
) -> tuple[bool, bool]:
    feed_ready, feed_reason = scheduler_bool(
        feed_complete,
        default=False,
        reason="queue_terminal_feed_complete_rejected",
    )
    no_live, live_reason = scheduler_bool(
        no_live_queue_work,
        default=False,
        reason="queue_terminal_no_live_work_rejected",
    )
    accounted, accounted_ok = accounting_int(
        accounted_files, field_name="accounted_files", report=report
    )
    total, total_ok = accounting_int(total_files, field_name="total_files", report=report)
    elapsed, elapsed_ok = accounting_float(
        idle_elapsed, field_name="idle_elapsed", report=report
    )
    grace, grace_ok = accounting_float(
        idle_grace_sec, field_name="idle_grace_sec", report=report
    )
    if feed_reason or live_reason:
        report_terminal_accounting_failure(
            report,
            "queue_terminal_accounting_input_rejected",
            ValueError(feed_reason or live_reason),
        )
        return False, True
    if not (accounted_ok and total_ok and elapsed_ok and grace_ok):
        return False, True
    if not (feed_ready and no_live and accounted < total):
        return False, False
    if elapsed < max(10.0, min(30.0, grace)):
        return False, False
    return True, False


def load_durable_queue_results(
    *,
    queue_dir: object,
    load_queue_file_results: Callable[[object], dict[str, object]],
    report: Callable[..., object],
) -> tuple[dict[str, object], bool]:
    try:
        return durable_results(load_queue_file_results(queue_dir), report=report), False
    except _TERMINAL_ACCOUNTING_EXCEPTIONS as exc:
        queue_text, queue_reason = scheduler_path_text(queue_dir)
        report_terminal_accounting_failure(
            report,
            "queue_missing_finalization_result_load_failed",
            exc,
            extra={"queue_dir": queue_text, "queue_dir_reason": queue_reason},
        )
        return {}, True


def missing_file_entries(
    *,
    all_files: Iterable[object],
    durable_now: dict[str, object],
    report: Callable[..., object],
) -> tuple[tuple[str, object], ...]:
    completed_paths = set(durable_now)
    return tuple(
        entry
        for entry in path_entries(all_files, report=report)
        if entry[0] not in completed_paths
    )


def materialize_missing_file_results(
    *,
    durable_now: dict[str, object],
    missing_entries: tuple[tuple[str, object], ...],
    worker_error_result: Callable[[object, BaseException], dict[str, object]],
    report: Callable[..., object],
) -> bool:
    had_error = False
    for file_key, path_error in missing_entries:
        try:
            error = path_error or RuntimeError(
                "queue drained with no pending/active/raw work but file had no durable result"
            )
            materialized = materialize_scheduler_mapping(
                worker_error_result(file_key, error)
            )
            if type(materialized) is not dict:
                raise ValueError(_WORKER_ERROR_RESULT_MAPPING_REJECTED)
            durable_now[file_key] = materialized
        except _TERMINAL_ACCOUNTING_EXCEPTIONS as exc:
            had_error = True
            report_terminal_accounting_failure(
                report,
                "queue_missing_finalization_error_result_failed",
                exc,
                extra={"file": file_key[:500]},
            )
    return had_error


def write_missing_file_results(
    *,
    outputs_dir: object,
    durable_now: dict[str, object],
    report: Callable[..., object],
) -> bool:
    try:
        if not durable_now:
            return False
        output_path, path_reason = scheduler_path_text(outputs_dir)
        if path_reason or output_path == "":
            raise ValueError(path_reason or "queue outputs path blank")
        write_result = write_worker_output_payload(
            Path(output_path) / "worker_missing_finalization.json",
            durable_now,
        )
        if write_result is True:
            return False
        report_terminal_accounting_failure(
            report,
            "queue_missing_finalization_write_rejected",
            RuntimeError("missing finalization output writer returned non-true"),
            extra={
                "outputs_dir": output_path,
                "write_result": scheduler_value_snapshot(
                    write_result,
                    field_name="missing_finalization_write_result",
                ),
            },
        )
    except _TERMINAL_ACCOUNTING_EXCEPTIONS as exc:
        output_text, output_reason = scheduler_path_text(outputs_dir)
        report_terminal_accounting_failure(
            report,
            "queue_missing_finalization_write_failed",
            exc,
            extra={"outputs_dir": output_text, "outputs_dir_reason": output_reason},
        )
    return True


def terminate_missing_finalization_workers(
    *,
    procs: Iterable[tuple[object, object, object, object]],
    terminate_worker: Callable[..., object],
    report: Callable[..., object],
    sleep: Callable[[float], object],
) -> None:
    terminate_processes(
        procs,
        actions=("terminate", "kill"),
        terminate_worker=terminate_worker,
        report=report,
        sleep=sleep,
        context="queue_missing_finalization",
    )
