"""Stage 1158: reporting/publication consumers use public persistence/reporting contracts."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.core.jsonio import read_json_file, validate_persistent_record_semantics
from Virus_Scan.runtime.resource_paths import build_scan_log_output_plan
from Virus_Scan.publication.virustotal_summary import build_virustotal_findings_summary
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult
from Virus_Scan.contracts.result_record import terminal_asset_engine_context


def _private_imports(path: str):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"), filename=path)
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name.startswith("_"):
                    offenders.append((node.lineno, node.module, alias.name))
    return offenders


def test_reporting_result_schema_uses_public_persistence_contracts():
    assert _private_imports("Virus_Scan/reporting/result_schema.py") == []


def test_virustotal_reporting_uses_public_reporting_contracts():
    assert _private_imports("Virus_Scan/virustotal/reporting.py") == []


def test_public_contracts_are_callable(tmp_path):
    payload = {"schema_version": 1, "file": "x", "result": {"file": "x", "classification": "benign", "score": 0.0}}
    p = tmp_path / "record.json"
    p.write_text('{"ok": true}', encoding="utf-8")
    assert read_json_file(p, default={}) == {"ok": True}
    assert validate_persistent_record_semantics(payload, context="stage1158") is True
    plan = build_scan_log_output_plan(scan_id="stage1158", root=tmp_path / "Scan Logs")
    assert plan.staging_report_path("scan_results.json").name == "scan_results.json"
    vt_summary = build_virustotal_findings_summary(
        scan_id="stage1158",
        snapshot_semantic_digest="a" * 64,
        local_results={},
        virustotal_result=VirusTotalReportingResult(
            status="unconfigured",
            config_digest="",
            config_path="",
            api_key_environment_variable="VIRUSTOTAL_API_KEY",
        ),
    )
    assert vt_summary.status == "unconfigured"
    assert vt_summary.counts_record()["finding_count"] == 0
    context, profile = terminal_asset_engine_context("game.rpy", ["renpy_script"])
    assert context["renpy"] == 1.0
    assert profile == "renpy"
