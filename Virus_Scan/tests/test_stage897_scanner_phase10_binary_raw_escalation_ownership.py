
"""Stage 897 Phase 10 binary raw escalation ownership tests."""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_raw_anchors import binary_raw_dangerous_anchor_hits
from Virus_Scan.scanners.binary_raw_escalation import (
    _umige_raw_should_escalate_after_triage_inmemory,
)
from Virus_Scan.scanners.config import load_binary_policy_snapshot
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest


def test_binary_raw_escalation_uses_scanner_owned_anchor_policy() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_raw_escalation.py"))
    tree = ast.parse(source)
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]
    assert "Virus_Scan.detection.tags.heuristics.dangerous_anchors" not in imports
    assert "Virus_Scan.runtime.structured_failures" not in imports
    assert "Virus_Scan.scanners.binary_raw_anchors" in imports
    assert "record_suppressed_failure" not in source


def test_binary_raw_anchor_policy_is_config_backed_and_immutable() -> None:
    policy = load_binary_policy_snapshot()
    assert "process_exec" in policy.raw_escalation_dangerous_anchor_tags
    assert "encoded_powershell" in policy.raw_escalation_dangerous_anchor_tags
    assert isinstance(policy.raw_escalation_dangerous_anchor_tags, frozenset)


def test_binary_raw_anchor_hits_are_deterministic_and_normalized() -> None:
    hits = binary_raw_dangerous_anchor_hits(
        ["benign", "Process_Exec", "encoded_powershell", "process_exec"]
    )
    assert hits == ("encoded_powershell", "process_exec")


def test_binary_raw_escalates_for_scanner_owned_dangerous_anchor(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"not suspicious by itself")

    assert _umige_raw_should_escalate_after_triage_inmemory(
        sample,
        ["process_exec"],
        False,
        {},
        "fast",
    ) is True


def test_binary_raw_escalation_removes_suppressed_failure_callsite() -> None:
    report = validate_suppressed_failure_manifest(Path("."))
    assert report["total_calls"] == 38
    assert report["unclassified"] == []
    assert not any(
        item["module"] == "Virus_Scan/scanners/binary_raw_escalation.py"
        for item in report["manifest"]
    )
