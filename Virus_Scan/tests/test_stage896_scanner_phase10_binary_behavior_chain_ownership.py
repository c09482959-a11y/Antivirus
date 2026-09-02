from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_behavior_chains import (
    binary_lolbin_chain,
    binary_scheduled_task_persistence,
)
from Virus_Scan.scanners.binary_behavior_detectors import detect_attack_chain

from Virus_Scan.scanners.config import load_binary_policy_snapshot
from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings


def test_binary_behavior_detectors_do_not_import_detection_private_chains():
    source = read_python_file(Path("Virus_Scan/scanners/binary_behavior_detectors.py"))
    tree = ast.parse(source)
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    ]
    assert "Virus_Scan.detection.tags.heuristics.execution_chains" not in imports
    assert "Virus_Scan.detection.tags.heuristics.persistence_chains" not in imports
    assert "Virus_Scan.scanners.binary_behavior_chains" in imports


def test_scanner_owned_lolbin_chain_preserves_binary_chain_score():
    score, hits = binary_lolbin_chain(
        ["network_download", "file_write", "process_exec", "scheduled_task"]
    )
    assert score == 17.5
    assert hits == ["download_write_persist_execute", "schtasks_persistence_execution"]


def test_scanner_owned_scheduled_task_chain_preserves_binary_score():
    score, hits = binary_scheduled_task_persistence(
        ["scheduled_task", "process_exec", "delayed_execution"]
    )
    assert score == 18.0
    assert hits == [
        "delayed execution staging",
        "scheduled execution chain",
        "schtasks persistence",
    ]


def test_detect_attack_chain_uses_scanner_owned_chain_helpers():
    score, hits = detect_attack_chain(
        [
            "network_download",
            "file_write",
            "process_exec",
            "scheduled_task",
            "delayed_execution",
        ],
    )
    assert score >= 35.5
    assert "download_write_persist_execute" in hits
    assert "scheduled execution chain" in hits


def test_binary_chain_policy_is_config_backed_and_audit_clean():
    policy = load_binary_policy_snapshot()
    assert policy.binary_lolbin_chain_definitions
    assert policy.binary_scheduled_task_persistence_rules
    assert scan_policy_table_config_findings("Virus_Scan/scanners") == ()
