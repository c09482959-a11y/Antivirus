
"""Stage 1984 graph public contract sentinel-output remediation."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from Virus_Scan.models.api import (
    graph_contracts,
    profile_contracts,
    profile_learning_contracts,
    profile_retention_contracts,
    replay_comparison_contracts,
    replay_economics_contracts,
)


class HostileNumeric:
    def __init__(self) -> None:
        self.float_calls = 0

    def __float__(self):  # pragma: no cover - failure proves caller hook execution
        self.float_calls += 1
        raise AssertionError("caller __float__ invoked")

    def __str__(self):  # pragma: no cover - failure proves caller hook execution
        raise AssertionError("caller __str__ invoked")

    def __repr__(self):  # pragma: no cover - failure proves caller hook execution
        raise AssertionError("caller __repr__ invoked")


class HostilePath:
    def __fspath__(self):  # pragma: no cover - failure proves caller hook execution
        raise AssertionError("caller __fspath__ invoked")

    def __str__(self):  # pragma: no cover - failure proves caller hook execution
        raise AssertionError("caller __str__ invoked")

    def __repr__(self):  # pragma: no cover - failure proves caller hook execution
        raise AssertionError("caller __repr__ invoked")


def _except_constant_returns(function_name: str) -> list[tuple[int, object]]:
    source_path = Path("Virus_Scan/models/api/graph_contracts.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    matches: list[tuple[int, object]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            for child in ast.walk(node):
                if isinstance(child, ast.ExceptHandler):
                    for statement in ast.walk(child):
                        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Constant):
                            if statement.value.value in {0, 0.0, False, True}:
                                matches.append((statement.lineno, statement.value.value))
    return matches


def test_stage1984_graph_risk_numeric_helper_uses_evidence_not_exception_sentinel() -> None:
    hostile = HostileNumeric()

    with patch.object(
        graph_contracts,
        "owner_get_graph_risk_enhanced_evidence",
        lambda _node: {
            "risk": hostile,
            "ready": False,
            "degraded": True,
            "unavailable_reason": "hostile_graph_risk",
            "evidence_type": "graph_risk",
            "final_json_must_record": True,
            "replay_record_required": True,
        },
    ):
        evidence = graph_contracts.get_graph_risk_enhanced_evidence("node")
        risk = graph_contracts.get_graph_risk_enhanced("node")

    assert isinstance(evidence, MappingProxyType)
    assert risk == 0.0
    assert hostile.float_calls == 0
    assert _except_constant_returns("get_graph_risk_enhanced") == []


def test_stage1984_archive_member_linking_exposes_degraded_evidence_for_invalid_public_path() -> None:
    hostile = HostilePath()

    evidence = graph_contracts.link_archive_members_to_graph_evidence(hostile)

    assert isinstance(evidence, MappingProxyType)
    assert evidence["linked"] == 0
    assert evidence["ready"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] == "graph_archive_path_public_input_invalid"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert graph_contracts.link_archive_members_to_graph(hostile) == 0
    assert "link_archive_members_to_graph_evidence" in graph_contracts.__all__
    assert _except_constant_returns("link_archive_members_to_graph") == []


def _api_except_constant_returns(source_path: Path, function_name: str) -> list[tuple[int, object]]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    matches: list[tuple[int, object]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            for child in ast.walk(node):
                if isinstance(child, ast.ExceptHandler):
                    for statement in ast.walk(child):
                        if isinstance(statement, ast.Return) and isinstance(statement.value, ast.Constant):
                            if statement.value.value in {0, 0.0, False, True}:
                                matches.append((statement.lineno, statement.value.value))
    return matches


def test_stage1984_profile_learning_and_replay_bool_helpers_use_evidence_not_exception_sentinels() -> None:
    hostile = HostilePath()

    profile_evidence = profile_contracts.validate_engine_profile_schema_evidence(
        hostile,
        expected_engine=hostile,
    )
    assert profile_evidence["valid"] is False
    assert profile_evidence["ready"] is False
    assert profile_evidence["degraded"] is True
    assert profile_contracts.validate_engine_profile_schema(hostile, expected_engine=hostile) is False

    with patch.object(
        profile_learning_contracts,
        "owner_learning_verdict_is_clean",
        lambda _verdict: hostile,
    ):
        learning_evidence = profile_learning_contracts.learning_verdict_is_clean_evidence("verdict")
        clean = profile_learning_contracts.learning_verdict_is_clean("verdict")
    assert learning_evidence["clean"] is False
    assert learning_evidence["ready"] is False
    assert learning_evidence["degraded"] is True
    assert clean is False

    with patch.object(
        replay_economics_contracts,
        "owner_replay_should_retain",
        lambda _result: hostile,
    ):
        retention_evidence = replay_economics_contracts.replay_should_retain_evidence("result")
        retain = replay_economics_contracts.replay_should_retain("result")
    assert retention_evidence["retain"] is True
    assert retention_evidence["ready"] is False
    assert retention_evidence["degraded"] is True
    assert retain is True

    assert _api_except_constant_returns(
        Path("Virus_Scan/models/api/profile_contracts.py"),
        "validate_engine_profile_schema",
    ) == []
    assert _api_except_constant_returns(
        Path("Virus_Scan/models/api/profile_learning_contracts.py"),
        "learning_verdict_is_clean",
    ) == []
    assert _api_except_constant_returns(
        Path("Virus_Scan/models/api/replay_economics_contracts.py"),
        "replay_should_retain",
    ) == []


def test_stage1984_profile_retention_mapping_text_safety_records_unavailable_evidence() -> None:
    hostile = HostilePath()

    evidence = profile_retention_contracts._retention_plain_mapping_text_evidence(hostile)

    assert evidence["safe"] is False
    assert evidence["ready"] is False
    assert evidence["degraded"] is True
    assert evidence["unavailable_reason"] == "profile_retention_mapping_items_unreadable"
    assert profile_retention_contracts._retention_plain_mapping_text_safe(hostile) is False
    assert _api_except_constant_returns(
        Path("Virus_Scan/models/api/profile_retention_contracts.py"),
        "_retention_plain_mapping_text_safe",
    ) == []


def test_stage1984_replay_comparison_freezes_mappings_without_public_keys_calls() -> None:
    source = read_python_file(Path("Virus_Scan/models/api/replay_comparison_contracts.py"))
    assert "tuple(value.keys())" not in source
    assert "keys = tuple(value.keys())" not in source
    assert "tuple(record.keys())" not in source

    class HostileMapping(dict):
        def keys(self):  # pragma: no cover - failure proves raw keys() was called
            raise AssertionError("caller keys invoked")

    comparison = replay_comparison_contracts.compare_model_evidence(
        model_name="stage1984",
        expected=HostileMapping({"a": 1}),
        actual=HostileMapping({"a": 2}),
    )

    assert comparison["matched"] is False
    assert comparison["mismatch_fields"] == ("actual", "expected")
    assert comparison["expected_unavailable_reason"] == "model_evidence_mapping_unreadable"
    assert comparison["actual_unavailable_reason"] == "model_evidence_mapping_unreadable"
