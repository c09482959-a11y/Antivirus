import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings
from Virus_Scan.scanners.config.contracts import ScannerConfigError
from Virus_Scan.scanners.config.loader import load_engine_policy_result, load_engine_policy_snapshot
from Virus_Scan.scanners.ilspy import USE_ILSPY


def test_phase7_policy_table_config_audit_has_no_findings():
    findings = scan_policy_table_config_findings("Virus_Scan/scanners")
    assert findings == ()


def test_ilspy_execution_flag_is_engine_policy_snapshot_owned(tmp_path):
    snapshot = load_engine_policy_snapshot()
    assert USE_ILSPY is snapshot.use_ilspy
    bad = tmp_path / "engine_policy.json"
    bad.write_text(
        '{"schema_version": 1, "use_ilspy": "yes", "unity_lifecycle_hooks": ["Start"], '
        '"unity_runtime_checks": [{"needle": "Assembly.Load", "tag": "assembly_load"}], '
        '"rpgm_encrypted_media_url_markers": ["http://"], '
        '"rpgm_decrypted_media_suspicious_tokens": ["cmd.exe"]}',
        encoding="utf-8",
    )
    result = load_engine_policy_result(bad)
    assert not result.ok
    assert result.failure is not None
    assert result.failure.config_name == "engine_policy"
    assert result.failure_evidence
    assert result.failure_evidence[0]["error_category"] == "scanner_config_validation_failure"


def test_binary_scanner_has_no_hidden_module_mutable_runtime_state():
    path = Path("Virus_Scan/scanners/binary.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = {"_UMIGE_DYNAMIC_STAGE_COST", "_UMIGE_CPU_SAMPLE_STATE"}
    assigned = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigned.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assigned.add(node.target.id)
    assert not (assigned & forbidden)
