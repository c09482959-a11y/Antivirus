from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.models.graph.common import safe_graph_text
from Virus_Scan.models.graph.method_graph import build_method_graph
from Virus_Scan.models.graph.relationships import phase_matches_from_tags
from Virus_Scan.models.graph.scan import scan_cs
from Virus_Scan.runtime.graph_state import graph_node_snapshot, reset_graph_state


GRAPH_SOURCES = tuple(sorted(Path("Virus_Scan/models/graph").glob("*.py")))


class HostileText:
    def __str__(self):  # pragma: no cover - failure means the boundary regressed
        raise AssertionError("text hook invoked")

    def __format__(self, _spec):  # pragma: no cover
        raise AssertionError("format hook invoked")

    def __repr__(self):  # pragma: no cover
        raise AssertionError("repr hook invoked")


class HostilePath:
    fspath_called = False

    def __fspath__(self):  # pragma: no cover
        type(self).fspath_called = True
        raise AssertionError("fspath hook invoked")

    def __str__(self):  # pragma: no cover
        raise AssertionError("path text hook invoked")


class HostileMapping(Mapping):
    items_called = False
    iter_called = False

    def __getitem__(self, key):  # pragma: no cover
        raise AssertionError("mapping item hook invoked")

    def __iter__(self):  # pragma: no cover
        type(self).iter_called = True
        raise AssertionError("mapping iter hook invoked")

    def __len__(self):  # pragma: no cover
        raise AssertionError("mapping len hook invoked")

    def items(self):  # pragma: no cover
        type(self).items_called = True
        raise AssertionError("mapping items hook invoked")

    def keys(self):  # pragma: no cover
        raise AssertionError("mapping keys hook invoked")

    def values(self):  # pragma: no cover
        raise AssertionError("mapping values hook invoked")


def test_stage1980_graph_sources_have_no_dynamic_fstrings_or_mapping_method_calls() -> None:
    offenders = []
    for path in GRAPH_SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        offenders.extend((path.as_posix(), node.lineno, "f-string") for node in ast.walk(tree) if isinstance(node, ast.JoinedStr))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"items", "keys", "values"}:
                offenders.append((path.as_posix(), node.lineno, node.func.attr))
    assert offenders == []


def test_stage1980_graph_text_boundary_rejects_hostile_text_without_hooks() -> None:
    assert safe_graph_text(HostileText()) == "unsupported_graph_text_type:HostileText"


def test_stage1980_graph_scan_rejects_hostile_path_without_fspath_hook() -> None:
    HostilePath.fspath_called = False

    assert scan_cs(HostilePath()) == ["graph_cs_scan_unavailable"]
    assert HostilePath.fspath_called is False


def test_stage1980_graph_relationship_and_method_inputs_reject_custom_mappings() -> None:
    HostileMapping.items_called = False
    HostileMapping.iter_called = False
    reset_graph_state()

    assert phase_matches_from_tags(("execution",), attack_graph=HostileMapping()) == {}
    build_method_graph("sample.cs", HostileMapping())

    assert graph_node_snapshot("sample.cs::Run") is None
    assert HostileMapping.items_called is False
    assert HostileMapping.iter_called is False

