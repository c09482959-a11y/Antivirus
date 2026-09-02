from __future__ import annotations

import inspect
from pathlib import Path

from Virus_Scan.models.api import (
    clustering_contracts,
    graph_contracts,
    profile_learning_contracts,
    profile_retention_contracts,
    temporal_contracts,
    text_boundary,
)


class HostileNameMeta(type):
    touched = 0

    def __getattribute__(cls, name):
        if name == "__name__":
            HostileNameMeta.touched += 1
            raise RuntimeError("metaclass __name__ hook must not execute")
        return super().__getattribute__(name)


class HostileModelApiValue(metaclass=HostileNameMeta):
    touched = 0

    def __str__(self):
        HostileModelApiValue.touched += 1
        raise RuntimeError("__str__ must not execute")

    def __repr__(self):
        HostileModelApiValue.touched += 1
        raise RuntimeError("__repr__ must not execute")

    def __format__(self, spec):
        HostileModelApiValue.touched += 1
        raise RuntimeError("__format__ must not execute")


class HostilePair(metaclass=HostileNameMeta):
    touched = 0

    def __getitem__(self, index):
        HostilePair.touched += 1
        raise RuntimeError("pair indexing must not execute")

    def __iter__(self):
        HostilePair.touched += 1
        raise RuntimeError("pair iteration must not execute")

    def __str__(self):
        HostilePair.touched += 1
        raise RuntimeError("pair str must not execute")

    def __repr__(self):
        HostilePair.touched += 1
        raise RuntimeError("pair repr must not execute")


def _reset_hooks() -> None:
    HostileNameMeta.touched = 0
    HostileModelApiValue.touched = 0
    HostilePair.touched = 0


def _assert_no_hooks() -> None:
    assert HostileNameMeta.touched == 0
    assert HostileModelApiValue.touched == 0
    assert HostilePair.touched == 0


def test_stage1763_public_api_sort_key_uses_no_hook_type_name() -> None:
    _reset_hooks()
    key = text_boundary.public_api_sort_key(HostileModelApiValue())
    assert key == (
        "<unreadable_HostileModelApiValue>",
        "unreadable_public_contract_text",
        "",
    )
    _assert_no_hooks()


def test_stage1763_model_api_materializers_do_not_call_type_name_or_text_hooks() -> None:
    _reset_hooks()
    value = HostileModelApiValue()
    payload = {"safe": {value}, value: {"nested": value}}

    cluster_value = clustering_contracts._immutable_cluster_value(payload)
    graph_value = graph_contracts._immutable_graph_value(payload)
    profile_learning_value = profile_learning_contracts._immutable_profile_learning_value(payload)
    profile_retention_value = profile_retention_contracts._immutable_retention_value(payload)
    temporal_value = temporal_contracts._materialize_temporal_value(payload)

    for materialized in (cluster_value, graph_value, profile_learning_value, profile_retention_value, temporal_value):
        assert materialized is not None
    _assert_no_hooks()


def test_stage1763_profile_retention_pair_sorting_type_name_is_no_hook() -> None:
    _reset_hooks()
    pair = HostilePair()
    value = profile_retention_contracts._immutable_retention_value({"pairs": {pair}})
    assert "pairs" in value
    _assert_no_hooks()


def test_stage1763_model_api_source_removed_type_name_hook_paths() -> None:
    modules = (
        clustering_contracts,
        graph_contracts,
        profile_learning_contracts,
        profile_retention_contracts,
        temporal_contracts,
        text_boundary,
    )
    for module in modules:
        source = inspect.getsource(module)
        assert "no_hook_type_name" in source
        assert "type(value).__name__" not in source
        assert "type(item).__name__" not in source
        assert "type(item[0]).__name__" not in source
    api_dir = Path("Virus_Scan/models/api")
    for path in api_dir.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        assert "type(value).__name__" not in source, str(path)
        assert "type(item).__name__" not in source, str(path)
        assert "type(item[0]).__name__" not in source, str(path)
