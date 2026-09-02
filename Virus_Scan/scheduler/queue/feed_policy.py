"""Process queue feed policy ownership.

Queue feed admission policy is separated from queue directory authority so the
queue-authority module does not also own dynamic-feed tuning semantics.
"""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.queue.feed_policy_contracts import ProcessQueueFeedDecision, ProcessQueueFeedPolicy
from Virus_Scan.scheduler.queue.feed_policy_scalars import feed_bool, feed_float, feed_int
from Virus_Scan.scheduler.runtime.env_policy import bool_env, float_env, int_env


def _owned_feed_policy(policy: object, *, target_workers: int) -> ProcessQueueFeedPolicy:
    del target_workers
    if type(policy) is ProcessQueueFeedPolicy:
        return policy
    raise ValueError("process_queue_feed_policy_rejected")


def build_process_queue_feed_policy(
    env: Mapping[str, str],
    *,
    target_workers: int,
    recoverable_exceptions: tuple[type[BaseException], ...],
) -> ProcessQueueFeedPolicy:
    owned_target_workers = feed_int(
        target_workers,
        minimum=1,
        reason="process_queue_feed_target_workers_rejected",
    )
    pending_multiplier = float_env(env, "UMIGE_DYNAMIC_QUEUE_PENDING_MULTIPLIER", 4.0, recoverable_exceptions)
    min_pending_buffer = int_env(env, "UMIGE_DYNAMIC_QUEUE_MIN_PENDING", 128, recoverable_exceptions)
    owned_min_pending_buffer = feed_int(
        min_pending_buffer,
        minimum=0,
        reason="process_queue_feed_min_pending_rejected",
    )
    owned_pending_multiplier = feed_float(
        pending_multiplier,
        minimum=0.5,
        reason="process_queue_feed_pending_multiplier_rejected",
    )
    pending_buffer = max(
        owned_min_pending_buffer,
        int(owned_target_workers * max(0.5, owned_pending_multiplier)),
    )
    max_file_feed_burst = int_env(
        env,
        "UMIGE_DYNAMIC_QUEUE_MAX_FEED_BURST",
        max(128, pending_buffer * 2),
        recoverable_exceptions,
    )
    pressure_pending_buffer = int_env(
        env,
        "UMIGE_DYNAMIC_QUEUE_PRESSURE_PENDING",
        max(96, owned_min_pending_buffer),
        recoverable_exceptions,
    )
    return ProcessQueueFeedPolicy(
        pending_multiplier=owned_pending_multiplier,
        min_pending_buffer=owned_min_pending_buffer,
        pending_buffer=pending_buffer,
        max_file_feed_burst=max_file_feed_burst,
        pressure_pending_buffer=pressure_pending_buffer,
        keep_pending_full=bool_env(env, "UMIGE_KEEP_FILE_PENDING_FULL", default=True, recoverable_exceptions=recoverable_exceptions),
    )


def initial_file_feed_buffer(process_count: int, target_workers: int, policy: ProcessQueueFeedPolicy) -> int:
    owned_process_count = feed_int(
        process_count,
        minimum=0,
        reason="process_queue_feed_process_count_rejected",
    )
    owned_target_workers = feed_int(
        target_workers,
        minimum=0,
        reason="process_queue_feed_target_workers_rejected",
    )
    owned_policy = _owned_feed_policy(policy, target_workers=owned_target_workers)
    policy_multiplier = feed_float(
        owned_policy.pending_multiplier,
        minimum=0.5,
        reason="process_queue_feed_pending_multiplier_rejected",
    )
    return max(
        owned_process_count,
        owned_target_workers + max(32, int(owned_target_workers * policy_multiplier)),
    )


def decide_process_queue_feed(
    *,
    target_workers: int,
    file_active_count: int,
    file_pending_count: int,
    io_pressure: bool,
    policy: ProcessQueueFeedPolicy,
) -> ProcessQueueFeedDecision:
    owned_target_workers = feed_int(
        target_workers,
        minimum=0,
        reason="process_queue_feed_target_workers_rejected",
    )
    owned_file_active_count = feed_int(
        file_active_count,
        minimum=0,
        reason="process_queue_feed_active_count_rejected",
    )
    owned_file_pending_count = feed_int(
        file_pending_count,
        minimum=0,
        reason="process_queue_feed_pending_count_rejected",
    )
    owned_io_pressure = feed_bool(
        io_pressure,
        reason="process_queue_feed_io_pressure_rejected",
    )
    owned_policy = _owned_feed_policy(policy, target_workers=owned_target_workers)
    pending_buffer = owned_policy.pending_buffer
    desired_file_live = max(owned_target_workers, owned_target_workers + pending_buffer)
    if owned_policy.keep_pending_full:
        target_pending_buffer = pending_buffer
        if owned_io_pressure:
            target_pending_buffer = max(1, min(pending_buffer, owned_policy.pressure_pending_buffer))
        feed_capacity = max(0, target_pending_buffer - owned_file_pending_count)
        feed_capacity = min(feed_capacity, max(1, owned_policy.max_file_feed_burst))
    else:
        current_file_live = owned_file_active_count + owned_file_pending_count
        feed_capacity = max(0, desired_file_live - current_file_live)
        if owned_io_pressure:
            feed_capacity = min(
                feed_capacity,
                max(0, owned_target_workers - owned_file_active_count - owned_file_pending_count),
            )
    return ProcessQueueFeedDecision(
        target_workers=owned_target_workers,
        pending_buffer=pending_buffer,
        desired_file_live=desired_file_live,
        feed_capacity=feed_capacity,
    )


__all__ = (
    "ProcessQueueFeedDecision",
    "ProcessQueueFeedPolicy",
    "build_process_queue_feed_policy",
    "decide_process_queue_feed",
    "initial_file_feed_buffer",
)
