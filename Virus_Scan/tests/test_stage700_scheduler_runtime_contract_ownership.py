from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, python_files_under


from Virus_Scan.scheduler.runtime.deep_scan_policy import scheduler_deep_scan_thorough

import ast
from pathlib import Path

from Virus_Scan.scheduler.runtime.passive_asset_triage import is_terminal_clean_asset_triage
from Virus_Scan.scheduler.runtime.raw_escalation_policy import should_escalate_after_inmemory_triage
from Virus_Scan.scheduler.workers.result_contracts import make_scheduler_cancel_result

ROOT = Path(__file__).resolve().parents[1]
SCHEDULER_ROOT = ROOT / "scheduler"


def _import_from_nodes(path: Path):
    return [node for node in ast.walk(parse_python_file(path)) if isinstance(node, ast.ImportFrom)]


def test_scheduler_workers_own_cancel_result_contract():
    path, result = make_scheduler_cancel_result("sample.bin", "cooperative-stop")
    assert path == "sample.bin"
    assert result["queue_failure"] is True
    assert result["scheduler_failure_reason"] == "cooperative-stop"
    assert result["cancelled_generation"] is True


def test_scheduler_runtime_owns_passive_triage_policy():
    assert is_terminal_clean_asset_triage(["media_asset"], suspicious=False) is True
    assert is_terminal_clean_asset_triage(["media_asset", "embedded_script_marker"], suspicious=False) is False
    assert is_terminal_clean_asset_triage(["media_asset"], suspicious=True) is False


def test_scheduler_runtime_owns_raw_escalation_policy():
    assert should_escalate_after_inmemory_triage("sample.exe", ["process_exec"], False, None, "binary") is True
    assert should_escalate_after_inmemory_triage("sample.png", ["media_asset"], False, None, "media") is False
    assert should_escalate_after_inmemory_triage("sample.bin", [], False, {"hits": ["x"]}, "binary") is True


def test_scheduler_no_longer_imports_private_result_or_triage_helpers():
    forbidden = {
        "_umige_cancel_result",
        "_make_worker_error_result",
        "_is_terminal_clean_asset_triage",
        "_umige_raw_should_escalate_after_triage_inmemory",
    }
    offenders = []
    for py_file in python_files_under("Virus_Scan/scheduler"):
        for node in _import_from_nodes(py_file):
            for alias in node.names:
                if alias.name in forbidden:
                    offenders.append(f"{py_file}:{node.lineno}:{alias.name}")
    assert offenders == []


def test_scheduler_deep_scan_policy_owns_thorough_query():

    assert isinstance(scheduler_deep_scan_thorough(), bool)


def test_scheduler_no_dead_private_direct_rpa_import():
    offenders = []
    for py_file in python_files_under("Virus_Scan/scheduler"):
        for node in _import_from_nodes(py_file):
            for alias in node.names:
                if alias.name in {"_make_direct_rpa_result", "deep_scan_thorough_enabled"}:
                    offenders.append(f"{py_file}:{node.lineno}:{alias.name}")
    assert offenders == []


def test_scheduler_has_no_private_cross_domain_import_names_after_phase4_slice():
    offenders = []
    for py_file in python_files_under("Virus_Scan/scheduler"):
        for node in _import_from_nodes(py_file):
            module = node.module or ""
            if not module.startswith("Virus_Scan.") or module.startswith("Virus_Scan.scheduler"):
                continue
            for alias in node.names:
                if alias.name.startswith("_"):
                    offenders.append(f"{py_file}:{node.lineno}:{module}:{alias.name}")
    assert offenders == []
