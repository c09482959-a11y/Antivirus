"""Stage 898: Phase 10 binary scanner must not import private detection internals."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.binary_behavior_predicates import _has_c2_behavior, _has_command_exec_behavior
from Virus_Scan.detection.scoring.behavior.bucket_validation import behavior_bucket_validation
from Virus_Scan.scanners.binary_micro_stage import micro_stage_collect
from Virus_Scan.scanners.binary_runtime_evidence import _remember_scan_evidence
from Virus_Scan.scanners.config.loader import load_binary_policy_snapshot


def test_binary_phase10_modules_do_not_import_detection_private_modules():
    offenders = []
    for path in sorted(Path("Virus_Scan/scanners").glob("binary*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            module = None
            if isinstance(node, ast.ImportFrom):
                module = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("Virus_Scan.detection"):
                        offenders.append((path.as_posix(), node.lineno, alias.name))
            if module and module.startswith("Virus_Scan.detection"):
                offenders.append((path.as_posix(), node.lineno, module))
    assert offenders == []


def test_binary_behavior_terms_are_schema_config_backed_and_active():
    policy = load_binary_policy_snapshot()
    assert "powershell" in policy.binary_command_execution_terms
    assert "beacon" in policy.binary_c2_tasking_terms
    assert _has_command_exec_behavior("CreateProcess then powershell") is True
    assert _has_c2_behavior("https://example.test beacon task shell exec(") is True


def test_binary_behavior_scoring_uses_detection_owned_semantics(tmp_path):
    sample = tmp_path / "payload.dll"
    sample.write_bytes(b"MZ" + b"\0" * 128)
    result = behavior_bucket_validation(
        "unity",
        sample,
        ["process_exec", "network_download", "credential_dump_attempt"],
        strings_blob="Process.Start DownloadString LSASS",
    )
    assert result["version"]
    assert result["records"]
    assert {record["bucket"] for record in result["records"]} >= {"os_execution", "network", "credential"}


def test_binary_micro_stage_and_scan_evidence_are_scanner_owned(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\0" * 128 + b"WriteProcessMemory CreateRemoteThread")
    assert {"pe_file", "pe_exe", "executable_file"}.issubset(set(micro_stage_collect("file_identity", sample)))
    assert "process_injection" in micro_stage_collect("pe_api", sample)
    publication = _remember_scan_evidence(sample, strings_blob="x", raw_sample=b"abc")
    assert publication["ok"] is True
    assert publication["cache_publication_request"]["kind"] == "scan_evidence_cache_write"
