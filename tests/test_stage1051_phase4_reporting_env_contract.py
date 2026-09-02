
"""Phase 4 regression tests for reporting env parsing through canonical contracts."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

from Virus_Scan.reporting.compact import print_compact_scan_report
from tests.support.env_override import temporary_environ


def test_reporting_compact_uses_public_env_contract_for_cli_cap():
    tree = parse_python_file(Path("Virus_Scan/reporting/compact.py"))
    source = read_python_file(Path("Virus_Scan/reporting/compact.py"))
    assert "from Virus_Scan.contracts.env_config import int_env" in source
    forbidden = "os.environ.get('UMIGE_CLI_MAX_MEDIUM_DISPLAY'"
    assert forbidden not in source


def test_reporting_compact_invalid_cli_cap_uses_contract_default(capsys):
    with temporary_environ({"UMIGE_CLI_MAX_MEDIUM_DISPLAY": "not-an-int"}):
        results = {"sample.exe": {"score": 25.0, "tags": ["process_exec"], "evidence": []}}
        print_compact_scan_report(results, "target", yara_active=False)
        out = capsys.readouterr().out
    assert "CLI Shown: 1 MEDIUM+" in out
    assert "Risk: MEDIUM" in out
