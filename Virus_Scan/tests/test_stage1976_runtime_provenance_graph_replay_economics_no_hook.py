from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.runtime.provenance_graph import ProvenanceGraphEvent, ProvenanceGraphStore
from Virus_Scan.runtime.replay_introspection import ReplayIntegrityReport
from Virus_Scan.runtime.resource_economics import (
    ResourceEconomicsConfig,
    cross_domain_pressure_budget,
)


class _HostileText:
    touched = 0

    def __str__(self) -> str:  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("caller-owned text hook executed")

    def __format__(self, spec: str) -> str:  # pragma: no cover - regression asserts no call
        type(self).touched += 1
        raise AssertionError("caller-owned format hook executed")


RUNTIME_SOURCES = (
    Path("Virus_Scan/runtime/provenance_graph.py"),
    Path("Virus_Scan/runtime/replay_introspection.py"),
    Path("Virus_Scan/runtime/resource_economics.py"),
)


def test_stage1976_provenance_graph_rejects_hostile_text_without_hooks() -> None:
    _HostileText.touched = 0

    event = ProvenanceGraphEvent.build(
        event_type=_HostileText(),
        subsystem=_HostileText(),
        payload={_HostileText(): _HostileText()},
        parent_ids=(_HostileText(),),
    )
    row = event.canonical()

    assert row["event_type"].startswith("provenance_graph_text_unavailable:")
    assert row["subsystem"].startswith("provenance_graph_text_unavailable:")
    assert row["parent_ids"][0].startswith("provenance_graph_text_unavailable:")
    assert next(iter(row["payload"])).startswith("provenance_graph_text_unavailable:")
    assert _HostileText.touched == 0


def test_stage1976_provenance_graph_duplicate_keys_remain_stable() -> None:
    store = ProvenanceGraphStore()
    event = ProvenanceGraphEvent.build(
        event_type="event",
        subsystem="runtime",
        payload={1: "numeric", "1": "text"},
    )
    store.append(event)

    payload = store.canonical_snapshot()["events"][0]["payload"]

    assert payload["1"] == "numeric"
    assert payload["1#2"] == "text"


def test_stage1976_replay_integrity_rejects_hostile_counts_without_hooks() -> None:
    _HostileText.touched = 0

    report = ReplayIntegrityReport(
        True,
        _HostileText(),
        0,
        0,
        0,
        0,
    )

    assert report.ok is False
    assert report.event_count == 0
    assert report.input_evidence[0]["reason"] == "replay_integrity_event_count_rejected"
    assert _HostileText.touched == 0


def test_stage1976_resource_economics_rejects_hostile_numbers_without_hooks() -> None:
    _HostileText.touched = 0

    with pytest.raises(ValueError, match="max_archive_fanout_score_rejected"):
        ResourceEconomicsConfig(max_archive_fanout_score=_HostileText())
    with pytest.raises(ValueError, match="invalid pressure value count: 1"):
        cross_domain_pressure_budget(_HostileText())

    assert _HostileText.touched == 0


def test_stage1976_runtime_sources_keep_repaired_fstring_rows_closed() -> None:
    hits: list[str] = []
    for path in RUNTIME_SOURCES:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                hits.append(str(path) + ":" + str(node.lineno) + ":f-string")
    assert hits == []
