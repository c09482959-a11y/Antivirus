from __future__ import annotations

from typing import Any, cast

from Virus_Scan.scheduler.contracts.queue_snapshot import QueueSnapshot
from Virus_Scan.scheduler.internal.immutable_outputs import (
    FrozenSchedulerMapping,
    immutable_mapping,
    materialize_scheduler_mapping,
)
from Virus_Scan.scheduler.queue.recovery_contract import RecoveryHistoryTransition


def _any_mapping(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value)


def test_stage1029_scheduler_immutable_mapping_sorts_mapping_keys_for_deterministic_json() -> None:
    left = immutable_mapping({"b": 2, "a": {"y": 2, "x": 1}})
    right = immutable_mapping({"a": {"x": 1, "y": 2}, "b": 2})

    assert isinstance(left, FrozenSchedulerMapping)
    assert tuple(left) == ("a", "b")
    assert tuple(_any_mapping(left["a"])) == ("x", "y")
    materialized_left = _any_mapping(materialize_scheduler_mapping(left))
    assert materialized_left == materialize_scheduler_mapping(right)
    assert list(materialized_left.keys()) == ["a", "b"]


def test_stage1029_scheduler_immutable_value_sorts_unordered_sets_recursively() -> None:
    snapshot = QueueSnapshot(
        phase="phase3",
        metadata={
            "tags": {"zeta", "alpha", "middle"},
            "nested": {"set": {"b", "a"}},
        },
        evidence=({"markers": {"two", "one"}},),
    )

    exported = snapshot.as_dict()
    metadata = _any_mapping(exported["metadata"])
    assert metadata["tags"] == ["alpha", "middle", "zeta"]
    assert _any_mapping(metadata["nested"])["set"] == ["a", "b"]
    assert cast(list[dict[str, Any]], exported["evidence"])[0]["markers"] == ["one", "two"]


def test_stage1029_recovery_transition_sorts_record_and_item_keys_without_retaining_mutable_state() -> None:
    record: dict[str, Any] = {"z": {"items": {"b", "a"}}, "a": 1}
    item: dict[str, Any] = {"reason": "retry", "nested": {"keys": {"y", "x"}}}
    transition = RecoveryHistoryTransition(record, item)

    record["z"]["items"].add("late")
    item["nested"]["keys"].add("late")

    transition_record = _any_mapping(transition.as_record())
    transition_item = _any_mapping(transition.as_item())
    assert list(transition_record.keys()) == ["a", "z"]
    assert _any_mapping(transition_record["z"])["items"] == ["a", "b"]
    assert list(transition_item.keys()) == ["nested", "reason"]
    assert _any_mapping(transition_item["nested"])["keys"] == ["x", "y"]
