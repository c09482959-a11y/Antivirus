from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.contracts.analytical_evidence import (
    analytical_family_counts,
    analytical_format_oddity_snapshot,
    analytical_optional_text,
)
from Virus_Scan.contracts.api_behavior import API_NAME_TEXT_UNAVAILABLE, canonical_api_text
from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.contracts.call_graph_projection import api_call_graph_features, immutable_api_call_graph


class HostileDefaultRepr:
    touched = 0

    def __str__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ must not run")


class HostileFloat:
    touched = 0

    def __float__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ must not run")


class HostileIterable:
    touched = 0

    def __iter__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned __iter__ must not run")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned mapping __iter__ must not run")

    def __len__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned mapping __len__ must not run")

    def __getitem__(self, key):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned mapping __getitem__ must not run")

    def get(self, key, default=None):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned mapping get must not run")

    def items(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned mapping items must not run")


class HostilePathLike:
    touched = 0

    def __fspath__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned __fspath__ must not run")

    def __str__(self):  # pragma: no cover - failure is any call
        type(self).touched += 1
        raise AssertionError("caller-owned __str__ must not run")


def _reset() -> None:
    for cls in (HostileDefaultRepr, HostileFloat, HostileIterable, HostileMapping, HostilePathLike):
        cls.touched = 0


def test_stage1550_analytical_text_path_entropy_and_tags_reject_hostile_hooks() -> None:
    _reset()

    assert analytical_optional_text(HostileDefaultRepr(), default="fallback") == "fallback"
    oddity = analytical_format_oddity_snapshot(
        path=HostilePathLike(),
        entropy=HostileFloat(),
        tags=HostileIterable(),
    )
    families = analytical_family_counts(HostileIterable())

    assert oddity["format"] == "default"
    assert oddity["ready"] is False
    assert oddity["unavailable_reason"] == "unsafe_entropy_numeric_value_rejected"
    assert all(value == 0 for value in families.values())
    assert HostileDefaultRepr.touched == 0
    assert HostilePathLike.touched == 0
    assert HostileFloat.touched == 0
    assert HostileIterable.touched == 0


def test_stage1550_behavior_rarity_rejects_hostile_flow_iteration_and_text() -> None:
    _reset()

    rarity = behavior_rarity_from_flow(
        HostileIterable(),
        {HostileDefaultRepr(): 20, "exec": HostileFloat()},
        min_support=1,
    )

    assert rarity == 0.0
    assert HostileIterable.touched == 0
    assert HostileDefaultRepr.touched == 0
    assert HostileFloat.touched == 0


def test_stage1550_api_call_graph_projection_rejects_hostile_iteration_and_mapping_methods() -> None:
    _reset()

    graph = immutable_api_call_graph(HostileIterable())
    features = api_call_graph_features(HostileMapping())

    assert dict(graph) == {}
    assert features == {"nodes": 0, "edges": 0, "density": 0.0}
    assert HostileIterable.touched == 0
    assert HostileMapping.touched == 0


def test_stage1550_api_behavior_text_rejects_hostile_str_without_fspath() -> None:
    _reset()

    assert canonical_api_text(HostileDefaultRepr()) == API_NAME_TEXT_UNAVAILABLE
    assert canonical_api_text(HostilePathLike()) == API_NAME_TEXT_UNAVAILABLE
    assert HostileDefaultRepr.touched == 0
    assert HostilePathLike.touched == 0
