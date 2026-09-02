from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.runtime.graph_state import (
    add_graph_edge_owned,
    graph_node_snapshot,
    graph_owner,
    graph_snapshot,
    graph_vector_node_key,
    reset_graph_state,
    update_graph_node_owned,
)


class HostileHooks:
    calls: list[str] = []

    @classmethod
    def record(cls, name: str) -> None:
        cls.calls.append(name)
        raise AssertionError(f"caller-owned {name} executed")

    @classmethod
    def reset(cls) -> None:
        cls.calls = []


class HostileMapping(Mapping):
    def __init__(self, data=None):
        self._data = dict(data or {})

    def __iter__(self):  # pragma: no cover - must never be called
        HostileHooks.record("__iter__")

    def __len__(self):  # pragma: no cover - must never be called
        HostileHooks.record("__len__")

    def __getitem__(self, key):  # pragma: no cover - must never be called
        HostileHooks.record("__getitem__")

    def keys(self):  # pragma: no cover - must never be called
        HostileHooks.record("keys")

    def items(self):  # pragma: no cover - must never be called
        HostileHooks.record("items")

    def values(self):  # pragma: no cover - must never be called
        HostileHooks.record("values")


class HostileFloat:
    def __float__(self):  # pragma: no cover - must never be called
        HostileHooks.record("__float__")

    def __int__(self):  # pragma: no cover - must never be called
        HostileHooks.record("__int__")


class HostileNameMeta(type):
    def __getattribute__(cls, name):  # pragma: no cover - must never be called for __name__
        if name == "__name__":
            HostileHooks.record("type.__name__")
        return super().__getattribute__(name)


class HostileName(metaclass=HostileNameMeta):
    def __str__(self):  # pragma: no cover - must never be called
        HostileHooks.record("__str__")


def test_stage1567_graph_snapshot_rejects_hostile_mapping_metadata_without_mapping_hooks() -> None:
    reset_graph_state()
    HostileHooks.reset()
    owner = graph_owner()
    owner.graph["node:hostile-mapping"] = {
        "edges": set(),
        "edge_time": {},
        "weights": {},
        "types": {},
        "risk": 0.0,
        "last_seen": 1.0,
        "attention": 0.0,
        "tags": set(),
        "metadata": HostileMapping({"unsafe": "value"}),
    }

    snapshot = graph_snapshot()["node:hostile-mapping"]

    assert snapshot["metadata"]["unavailable_reason"] == "non_materializable_graph_mapping"
    assert HostileHooks.calls == []


def test_stage1567_graph_node_snapshot_rejects_corrupt_node_mapping_without_hooks() -> None:
    reset_graph_state()
    HostileHooks.reset()
    graph_owner().graph["node:corrupt"] = HostileMapping({"risk": 1.0})

    snapshot = graph_node_snapshot("node:corrupt")

    assert snapshot is not None
    assert snapshot["unavailable_reason"] == "non_materializable_graph_node_snapshot"
    assert HostileHooks.calls == []


def test_stage1567_graph_numeric_boundaries_do_not_call_hostile_numeric_hooks() -> None:
    reset_graph_state()
    HostileHooks.reset()

    add_graph_edge_owned("src", "dst", weight=HostileFloat())
    update_graph_node_owned("src", risk=HostileFloat(), attention=HostileFloat(), weights=HostileMapping({"dst": 1.0}))
    snapshot = graph_node_snapshot("src")

    assert snapshot is not None
    assert snapshot["risk"] == 0.0
    assert snapshot["attention"] == 0.0
    assert snapshot["risk_unavailable_reason"] == "non_finite_graph_risk"
    assert snapshot["attention_unavailable_reason"] == "non_finite_graph_attention"
    assert snapshot["weights"] == {}
    assert HostileHooks.calls == []


def test_stage1567_graph_vector_key_does_not_call_hostile_type_name_or_str() -> None:
    HostileHooks.reset()

    text = graph_vector_node_key(HostileName())

    assert text.startswith("graph_runtime_text_unavailable:")
    assert HostileHooks.calls == []
