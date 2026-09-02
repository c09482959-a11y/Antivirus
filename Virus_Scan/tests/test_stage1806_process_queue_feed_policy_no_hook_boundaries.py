from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.scheduler.queue.feed_policy import (
    ProcessQueueFeedPolicy,
    build_process_queue_feed_policy,
    decide_process_queue_feed,
    initial_file_feed_buffer,
)


RECOVERABLE = (ValueError, TypeError)


class HostileFeedValue:
    str_calls = 0
    repr_calls = 0
    format_calls = 0
    bool_calls = 0
    iter_calls = 0
    float_calls = 0
    int_calls = 0
    getattribute_calls = 0

    @classmethod
    def reset(cls) -> None:
        cls.str_calls = 0
        cls.repr_calls = 0
        cls.format_calls = 0
        cls.bool_calls = 0
        cls.iter_calls = 0
        cls.float_calls = 0
        cls.int_calls = 0
        cls.getattribute_calls = 0

    @classmethod
    def total_calls(cls) -> int:
        return (
            cls.str_calls
            + cls.repr_calls
            + cls.format_calls
            + cls.bool_calls
            + cls.iter_calls
            + cls.float_calls
            + cls.int_calls
            + cls.getattribute_calls
        )

    def __getattribute__(self, name: str):  # pragma: no cover - must never execute
        type(self).getattribute_calls += 1
        raise RuntimeError(f"feed value attribute access is forbidden: {name}")

    def __str__(self):  # pragma: no cover - must never execute
        type(self).str_calls += 1
        raise RuntimeError("feed value stringification is forbidden")

    def __repr__(self):  # pragma: no cover - must never execute
        type(self).repr_calls += 1
        raise RuntimeError("feed value repr is forbidden")

    def __format__(self, spec):  # pragma: no cover - must never execute
        type(self).format_calls += 1
        raise RuntimeError("feed value formatting is forbidden")

    def __bool__(self):  # pragma: no cover - must never execute
        type(self).bool_calls += 1
        raise RuntimeError("feed value truth testing is forbidden")

    def __iter__(self):  # pragma: no cover - must never execute
        type(self).iter_calls += 1
        raise RuntimeError("feed value iteration is forbidden")

    def __float__(self):  # pragma: no cover - must never execute
        type(self).float_calls += 1
        raise RuntimeError("feed value float conversion is forbidden")

    def __int__(self):  # pragma: no cover - must never execute
        type(self).int_calls += 1
        raise RuntimeError("feed value int conversion is forbidden")


def test_stage1806_feed_policy_rejects_hostile_target_workers_without_hooks():
    HostileFeedValue.reset()

    with pytest.raises(ValueError, match="process_queue_feed_target_workers_rejected"):
        build_process_queue_feed_policy(
            {},
            target_workers=HostileFeedValue(),
            recoverable_exceptions=RECOVERABLE,
        )

    assert HostileFeedValue.total_calls() == 0


def test_stage1806_initial_file_feed_buffer_rejects_hostile_inputs_without_hooks():
    HostileFeedValue.reset()

    with pytest.raises(ValueError, match="process_queue_feed_process_count_rejected"):
        initial_file_feed_buffer(
            HostileFeedValue(),
            HostileFeedValue(),
            HostileFeedValue(),
        )

    assert HostileFeedValue.total_calls() == 0


def test_stage1806_feed_decision_rejects_hostile_inputs_without_hooks():
    HostileFeedValue.reset()
    policy = ProcessQueueFeedPolicy(
        pending_multiplier=2.0,
        min_pending_buffer=8,
        pending_buffer=8,
        max_file_feed_burst=6,
        pressure_pending_buffer=3,
        keep_pending_full=True,
    )

    with pytest.raises(ValueError, match="process_queue_feed_target_workers_rejected"):
        decide_process_queue_feed(
            target_workers=HostileFeedValue(),
            file_active_count=HostileFeedValue(),
            file_pending_count=HostileFeedValue(),
            io_pressure=HostileFeedValue(),
            policy=policy,
        )

    assert HostileFeedValue.total_calls() == 0


def test_stage1806_feed_decision_rejects_hostile_policy_without_hooks():
    HostileFeedValue.reset()

    with pytest.raises(ValueError, match="process_queue_feed_policy_rejected"):
        decide_process_queue_feed(
            target_workers=4,
            file_active_count=1,
            file_pending_count=2,
            io_pressure=True,
            policy=HostileFeedValue(),
        )

    assert HostileFeedValue.total_calls() == 0


def test_stage1806_feed_decision_preserves_exact_text_scalars():
    policy = ProcessQueueFeedPolicy(
        pending_multiplier="2",
        min_pending_buffer="8",
        pending_buffer="8",
        max_file_feed_burst="6",
        pressure_pending_buffer="3",
        keep_pending_full="true",
    )

    assert initial_file_feed_buffer("2", "4", policy) == 36
    decision = decide_process_queue_feed(
        target_workers="4",
        file_active_count="1",
        file_pending_count="2",
        io_pressure="true",
        policy=policy,
    )

    assert decision.target_workers == 4
    assert decision.pending_buffer == 8
    assert decision.desired_file_live == 12
    assert decision.feed_capacity == 1


def test_stage1880_feed_policy_source_has_no_clean_scalar_rejection_substitutes():
    root = Path(__file__).resolve().parents[2]
    checked = (
        root / "Virus_Scan" / "scheduler" / "queue" / "feed_policy.py",
        root / "Virus_Scan" / "scheduler" / "queue" / "feed_policy_scalars.py",
    )
    violations = {path.name: line for path in checked for line in path.read_text().splitlines() if "fallback=" in line}
    assert violations == {}


def test_stage1880_feed_policy_dataclass_rejects_hostile_fields_without_hooks():
    HostileFeedValue.reset()

    with pytest.raises(ValueError, match="process_queue_feed_pending_multiplier_rejected"):
        ProcessQueueFeedPolicy(
            pending_multiplier=HostileFeedValue(),
            min_pending_buffer=8,
            pending_buffer=8,
            max_file_feed_burst=6,
            pressure_pending_buffer=3,
            keep_pending_full=True,
        )

    assert HostileFeedValue.total_calls() == 0
