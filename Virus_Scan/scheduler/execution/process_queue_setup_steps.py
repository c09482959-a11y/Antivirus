"""Bounded process-queue setup step helpers."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_minimum_int
from Virus_Scan.scheduler.execution.process_queue_setup_support import (
    process_queue_setup_cpu_text,
    process_queue_setup_log_message,
    process_queue_setup_nonnegative_int_or,
    process_queue_setup_weight,
)


def build_ordered_process_queue_items(all_files: tuple[object, ...], weight_for_path: object) -> tuple[tuple[int, int, object], ...]:
    """Return process-queue items ordered by scheduler-owned weights."""
    return tuple(
        (order, orig_idx, file_path)
        for order, (orig_idx, file_path) in enumerate(
            sorted(
                enumerate(all_files),
                key=lambda item: process_queue_setup_weight(weight_for_path(item[1])),
                reverse=True,
            )
        )
    )


def publish_static_process_queue_jobs(queue_dir: object, all_files: tuple[object, ...], deps: object) -> tuple[int, int, frozenset[object]]:
    """Publish all queue jobs for non-dynamic process-queue setup."""
    deps.write_jobs(queue_dir, all_files)
    deps.mark_feed_complete(queue_dir)
    return len(all_files), len(all_files), frozenset()


def publish_dynamic_process_queue_jobs(
    queue_dir: object,
    ordered_queue_items: tuple[tuple[int, int, object], ...],
    request: object,
    deps: object,
) -> tuple[int, int, frozenset[object]]:
    """Publish initial dynamic queue feed without caller-owned coercion hooks."""
    queue_feed_cursor = 0
    queue_enqueued_identities: set[object] = set()
    target_workers_raw, cpu_sample = deps.dynamic_process_queue_target(
        request.process_count,
        request.requested_process_count,
    )
    target_workers, _target_reason = process_queue_setup_nonnegative_int_or(
        target_workers_raw,
        request.process_count,
        reason="process_queue_setup_target_workers_rejected",
    )
    feed_policy = deps.build_feed_policy(
        request.env,
        target_workers=target_workers,
        recoverable_exceptions=deps.recoverable_exceptions,
    )
    initial_buffer_raw = deps.initial_file_feed_buffer(
        request.process_count,
        target_workers,
        feed_policy,
    )
    initial_buffer, _buffer_reason = scheduler_minimum_int(
        initial_buffer_raw,
        minimum=0,
        reason="process_queue_setup_initial_buffer_rejected",
    )
    queue_feed_cursor_raw, fed_now_raw, _skipped_now = deps.write_jobs_slice(
        queue_dir,
        ordered_queue_items,
        queue_feed_cursor,
        initial_buffer,
        queue_enqueued_identities,
    )
    queue_feed_cursor, _cursor_reason = process_queue_setup_nonnegative_int_or(
        queue_feed_cursor_raw,
        queue_feed_cursor,
        reason="process_queue_setup_feed_cursor_rejected",
    )
    fed_now, _fed_reason = scheduler_minimum_int(
        fed_now_raw,
        minimum=0,
        reason="process_queue_setup_fed_now_rejected",
    )
    if queue_feed_cursor >= len(ordered_queue_items):
        deps.mark_feed_complete(queue_dir)
    deps.log_info(
        process_queue_setup_log_message(
            fed_now=fed_now,
            total_files=len(request.all_files),
            target_workers=target_workers,
            cpu_text=process_queue_setup_cpu_text(cpu_sample),
        )
    )
    return queue_feed_cursor, fed_now, frozenset(queue_enqueued_identities)
