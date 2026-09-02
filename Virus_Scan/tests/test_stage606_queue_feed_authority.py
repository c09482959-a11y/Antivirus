from dataclasses import FrozenInstanceError

from Virus_Scan.scheduler.queue.feed_policy import (
    ProcessQueueFeedDecision,
    ProcessQueueFeedPolicy,
    build_process_queue_feed_policy,
    decide_process_queue_feed,
    initial_file_feed_buffer,
)


def test_queue_feed_policy_is_owned_by_queue_authority():
    policy = build_process_queue_feed_policy(
        {"UMIGE_DYNAMIC_QUEUE_PENDING_MULTIPLIER": "2", "UMIGE_DYNAMIC_QUEUE_MIN_PENDING": "8"},
        target_workers=4,
        recoverable_exceptions=(ValueError, TypeError),
    )
    assert isinstance(policy, ProcessQueueFeedPolicy)
    assert policy.pending_buffer == 8
    assert initial_file_feed_buffer(2, 4, policy) == 36


def test_queue_feed_decision_is_immutable_queue_authority_output():
    policy = ProcessQueueFeedPolicy(
        pending_multiplier=2.0,
        min_pending_buffer=8,
        pending_buffer=8,
        max_file_feed_burst=6,
        pressure_pending_buffer=3,
        keep_pending_full=True,
    )
    decision = decide_process_queue_feed(
        target_workers=4,
        file_active_count=1,
        file_pending_count=2,
        io_pressure=True,
        policy=policy,
    )
    assert isinstance(decision, ProcessQueueFeedDecision)
    assert decision.feed_capacity == 1
    try:
        decision.feed_capacity = 99
    except FrozenInstanceError:
        pass
    else:  # pragma: no cover - frozen dataclass must reject mutation
        raise AssertionError("queue feed decision must be immutable")
