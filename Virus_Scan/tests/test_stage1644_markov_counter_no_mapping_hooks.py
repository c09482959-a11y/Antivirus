from __future__ import annotations

from Virus_Scan.models.markov.counters import (
    counter_support,
    counter_target_count,
    markov_count_value,
    snapshot_transition_counter,
)


class HostileMarkovMapping:
    touched = 0

    def items(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("items hook must not execute")

    def get(self, key, default=None):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("get hook must not execute")

    def __iter__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("iter hook must not execute")

    def __len__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("len hook must not execute")

    def __getitem__(self, key):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("getitem hook must not execute")


class HostileMarkovCount:
    touched = 0

    def __float__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("float hook must not execute")

    def __int__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("int hook must not execute")

    def __eq__(self, other):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("eq hook must not execute")


class HostileSnapshotKey:
    touched = 0

    def __eq__(self, other):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("key equality hook must not execute")

    def __hash__(self):  # pragma: no cover - regression asserts no execution
        type(self).touched += 1
        raise AssertionError("key hash hook must not execute")


def test_stage1644_markov_counter_support_rejects_mapping_like_object_without_hooks() -> None:
    HostileMarkovMapping.touched = 0
    hostile = HostileMarkovMapping()

    assert counter_support(hostile) == (0, 0, "unreadable_markov_transition_counter")
    assert counter_target_count(hostile, "target") == (0, "unreadable_markov_target_count")
    assert snapshot_transition_counter(hostile, ("markov_context_support_v2", "target")) == ({}, "unreadable_markov_snapshot")

    assert HostileMarkovMapping.touched == 0


def test_stage1644_markov_count_value_rejects_numeric_like_object_without_hooks() -> None:
    HostileMarkovCount.touched = 0

    assert markov_count_value(HostileMarkovCount()) == (None, "non_numeric_markov_count")

    assert HostileMarkovCount.touched == 0


def test_stage1644_markov_snapshot_key_matching_does_not_execute_hostile_key_equality() -> None:
    HostileSnapshotKey.touched = 0
    key = ("markov_context_support_v2", "safe")
    snapshot = {key: {"target": 4}}

    assert snapshot_transition_counter(snapshot, HostileSnapshotKey()) == ({}, "")
    assert snapshot_transition_counter(snapshot, key) == ({"target": 4}, "")

    assert HostileSnapshotKey.touched == 0
