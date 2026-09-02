from Virus_Scan.contracts.markov_learning import (
    markov_event_transition_key,
    markov_global_context_key,
    markov_stage_transition_key,
)
from Virus_Scan.models.markov import markov_pair_probability, markov_stage_probability


def _event_key():
    return markov_event_transition_key(
        context_key=markov_global_context_key(), previous_stage="archive", source_event="download",
    )


def _stage_key():
    return markov_stage_transition_key(
        context_key=markov_global_context_key(), previous_stage="archive", behavior_flow=("download", "exec"),
    )


class _HostileSnapshotGet:
    touched = 0

    def get(self, *_args, **_kwargs):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("snapshot unavailable")


class _HostileCounterItems:
    touched = 0

    def items(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("counter unavailable")

    def get(self, *_args, **_kwargs):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        return 1


class _HostileCounterGet:
    touched = 0

    def items(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        return (("exec", 3),)

    def get(self, *_args, **_kwargs):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("target unavailable")


class _HostileCount:
    touched = 0

    def __float__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise RuntimeError("count unavailable")


def test_stage1469_markov_snapshot_get_failure_returns_explicit_unavailable_record():
    _HostileSnapshotGet.touched = 0
    record = markov_pair_probability("download", "exec", prev_stage="archive", snapshot=_HostileSnapshotGet())

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "unreadable_markov_snapshot"
    assert _HostileSnapshotGet.touched == 0


def test_stage1469_markov_transition_counter_iteration_failure_is_not_fake_cold_start():
    _HostileCounterItems.touched = 0
    record = markov_pair_probability("download", "exec", prev_stage="archive", snapshot={_event_key(): _HostileCounterItems()})

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "unreadable_markov_transition_counter"
    assert _HostileCounterItems.touched == 0


def test_stage1469_markov_target_count_failure_is_explicit():
    _HostileCounterGet.touched = 0
    record = markov_pair_probability("download", "exec", prev_stage="archive", snapshot={_event_key(): _HostileCounterGet()})

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "unreadable_markov_transition_counter"
    assert record["support"] == 0
    assert _HostileCounterGet.touched == 0


def test_stage1469_markov_stage_probability_rejects_hostile_counts_without_crashing():
    _HostileCount.touched = 0
    record = markov_stage_probability("archive", ["download", "exec"], "runtime", snapshot={_stage_key(): {"runtime": _HostileCount()}})

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_numeric_markov_count"
    assert _HostileCount.touched == 0
