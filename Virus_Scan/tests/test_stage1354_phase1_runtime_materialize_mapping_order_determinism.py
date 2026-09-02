from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.runtime.immutable_core import materialize_runtime_value
from Virus_Scan.runtime.mutation_coordinator import RuntimeEvent


def test_stage1354_materialize_runtime_value_sorts_mapping_keys_recursively() -> None:
    left = {
        "z": {"b": 2, "a": 1},
        "a": MappingProxyType({"d": 4, "c": 3}),
    }
    right = {
        "a": MappingProxyType({"c": 3, "d": 4}),
        "z": {"a": 1, "b": 2},
    }

    assert materialize_runtime_value(left) == materialize_runtime_value(right)
    assert list(materialize_runtime_value(left).keys()) == ["a", "z"]
    assert list(materialize_runtime_value(left)["a"].keys()) == ["c", "d"]
    assert list(materialize_runtime_value(left)["z"].keys()) == ["a", "b"]


def test_stage1354_runtime_mutation_event_materializes_payload_deterministically() -> None:
    first = RuntimeEvent(
        domain="runtime",
        kind="profile_model",
        timestamp=1.0,
        seq=1,
        payload={"z": {"b": 2, "a": 1}, "a": {"d": 4, "c": 3}},
    ).as_dict()
    second = RuntimeEvent(
        domain="runtime",
        kind="profile_model",
        timestamp=1.0,
        seq=1,
        payload={"a": {"c": 3, "d": 4}, "z": {"a": 1, "b": 2}},
    ).as_dict()

    assert first == second
    assert list(first["payload"].keys()) == ["a", "z"]
    assert list(first["payload"]["a"].keys()) == ["c", "d"]
