from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings


def test_stage1015_policy_config_audit_does_not_mutate_ast_nodes() -> None:
    source_path = Path("Virus_Scan/scanners/ci/policy_table_config_audit.py")
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=source_path.as_posix())

    setattr_calls: list[int] = []
    parent_attribute_writes: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "setattr":
            setattr_calls.append(node.lineno)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr == "parent":
                    parent_attribute_writes.append(node.lineno)

    assert setattr_calls == []
    assert parent_attribute_writes == []


def test_stage1015_policy_config_audit_still_scans_scanner_tree() -> None:
    findings = scan_policy_table_config_findings("Virus_Scan/scanners")

    assert isinstance(findings, tuple)
    assert all(finding.path.startswith("Virus_Scan/scanners") for finding in findings)
