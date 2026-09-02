from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_raw_escalation import (
    _umige_raw_should_escalate_after_triage_inmemory,
)


def test_raw_escalation_has_no_constant_true_dead_branch():
    source = read_python_file(Path("Virus_Scan/scanners/binary_raw_escalation.py"))
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            rendered = ast.unparse(node.test)
            assert rendered not in {"False", "bool(False)"}


def test_raw_escalation_still_escalates_on_explicit_error_tags():
    assert _umige_raw_should_escalate_after_triage_inmemory(
        "sample.bin",
        ["binary_raw_escalation_tag_parse_error"],
        False,
        {},
        "fast",
    ) is True


def test_raw_escalation_remains_false_without_triggering_evidence_or_signals():
    assert _umige_raw_should_escalate_after_triage_inmemory(
        "sample.bin",
        ["benign_binary_observation"],
        False,
        {},
        "fast",
    ) is False
