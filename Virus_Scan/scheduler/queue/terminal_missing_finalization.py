"""Explicit failed-result synthesis for vanished queue accounting."""
from __future__ import annotations

from typing import Callable, Iterable

from Virus_Scan.scheduler.queue.terminal_accounting_evidence import (
    terminal_missing_results_message,
)
from Virus_Scan.scheduler.queue.terminal_missing_finalization_support import (
    load_durable_queue_results,
    materialize_missing_file_results,
    missing_file_entries,
    terminal_accounting_ready,
    terminate_missing_finalization_workers,
    write_missing_file_results,
)


def finalize_missing_file_accounting(
    *,
    feed_complete: bool,
    no_live_queue_work: bool,
    accounted_files: int,
    total_files: int,
    idle_elapsed: float,
    idle_grace_sec: float,
    all_files: Iterable[object],
    queue_dir: object,
    outputs_dir: object,
    procs: Iterable[tuple[object, object, object, object]],
    load_queue_file_results: Callable[[object], dict[str, object]],
    worker_error_result: Callable[[object, BaseException], dict[str, object]],
    terminate_worker: Callable[..., object],
    report: Callable[..., object],
    log_error: Callable[[str], object],
    sleep: Callable[[float], object],
) -> tuple[bool, bool]:
    ready, had_error = terminal_accounting_ready(
        feed_complete=feed_complete,
        no_live_queue_work=no_live_queue_work,
        accounted_files=accounted_files,
        total_files=total_files,
        idle_elapsed=idle_elapsed,
        idle_grace_sec=idle_grace_sec,
        report=report,
    )
    if not ready:
        return False, had_error
    durable_now, load_had_error = load_durable_queue_results(
        queue_dir=queue_dir,
        load_queue_file_results=load_queue_file_results,
        report=report,
    )
    missing_entries = missing_file_entries(
        all_files=all_files,
        durable_now=durable_now,
        report=report,
    )
    materialize_had_error = materialize_missing_file_results(
        durable_now=durable_now,
        missing_entries=missing_entries,
        worker_error_result=worker_error_result,
        report=report,
    )
    write_had_error = write_missing_file_results(
        outputs_dir=outputs_dir,
        durable_now=durable_now,
        report=report,
    )
    had_error = had_error or load_had_error or materialize_had_error or write_had_error
    log_error(terminal_missing_results_message(len(missing_entries)))
    terminate_missing_finalization_workers(
        procs=procs,
        terminate_worker=terminate_worker,
        report=report,
        sleep=sleep,
    )
    return True, bool(missing_entries) or had_error


__all__ = ("finalize_missing_file_accounting",)
