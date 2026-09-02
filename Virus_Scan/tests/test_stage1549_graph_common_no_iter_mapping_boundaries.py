from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.graph.common import safe_graph_metadata_value, safe_graph_sequence
from Virus_Scan.models.graph import phase_matches_from_tags


class HostileIterable:
    touched = 0

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not iterate")


class HostileMapping(Mapping):
    touched = 0

    def __iter__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not iterate")

    def __getitem__(self, key):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not index")

    def __len__(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not len")

    def get(self, key, default=None):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not get")

    def items(self):  # pragma: no cover - test fails if invoked
        type(self).touched += 1
        raise RuntimeError("do not items")


def test_stage1549_graph_sequence_rejects_unknown_iterable_without_iterating() -> None:
    HostileIterable.touched = 0
    seq, reason = safe_graph_sequence(HostileIterable(), "graph_sequence_unavailable")

    assert seq == ()
    assert reason == "graph_sequence_unavailable"
    assert HostileIterable.touched == 0


def test_stage1549_graph_metadata_rejects_unknown_mapping_without_hooks() -> None:
    HostileMapping.touched = 0
    value, reason = safe_graph_metadata_value(HostileMapping(), "risk")

    assert value == ""
    assert reason == "unreadable_graph_metadata"
    assert HostileMapping.touched == 0


def test_stage1549_phase_matching_rejects_unknown_iterables_without_iterating() -> None:
    HostileIterable.touched = 0
    matches = phase_matches_from_tags(HostileIterable(), attack_graph={"credential": {"nodes": HostileIterable()}})

    assert matches == {}
    assert HostileIterable.touched == 0
