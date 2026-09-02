"""Stage 902 Phase 10 binary runtime-dependency ownership tests."""

from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.binary_behavior_detectors import detect_evasion_signals
from Virus_Scan.scanners.binary_io import binary_string_evidence_tags, read_binary_file_bytes
from Virus_Scan.scanners.binary_pe_evidence import mark_pe_helper_error
from Virus_Scan.scanners.config import load_binary_policy_snapshot
from Virus_Scan.scanners.ci.policy_table_config_audit import scan_policy_table_config_findings
from Virus_Scan.scanners.ci.suppressed_failure_audit import validate_suppressed_failure_manifest


def _binary_sources() -> dict[Path, str]:
    return {
        path: path.read_text(encoding="utf-8")
        for path in Path("Virus_Scan/scanners").glob("binary*.py")
    }


def test_binary_phase10_modules_do_not_import_runtime_core_or_model_owners() -> None:
    forbidden_prefixes = (
        "Virus_Scan.runtime",
        "Virus_Scan.core",
        "Virus_Scan.routing",
        "Virus_Scan.models",
        "Virus_Scan.detection",
    )
    offenders: list[tuple[str, str, int]] = []
    for path, source in _binary_sources().items():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.startswith(forbidden_prefixes):
                    offenders.append((str(path), module, node.lineno))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(forbidden_prefixes):
                        offenders.append((str(path), alias.name, node.lineno))
    assert offenders == []


def test_binary_phase10_modules_do_not_hide_failures_with_suppressed_failure_calls() -> None:
    for path, source in _binary_sources().items():
        assert "record_suppressed_failure" not in source, str(path)
    report = validate_suppressed_failure_manifest(Path("."))
    assert report["total_calls"] == 38
    assert report["unclassified"] == []
    assert report["stale_manifest"] == []
    assert report["count_mismatches"] == []


def test_binary_string_policy_is_config_backed_and_deterministic() -> None:
    policy = load_binary_policy_snapshot()
    assert ("powershell", "powershell_exec") in policy.binary_string_rules
    assert ("downloadstring", "network_download") in policy.binary_string_rules
    tags = binary_string_evidence_tags("PowerShell -EncodedCommand AAAA DownloadString http://x")
    assert "powershell_exec" in tags
    assert "encoded_powershell" in tags
    assert "network_download" in tags
    assert "url_present" in tags
    assert "download_observable" in tags
    assert scan_policy_table_config_findings("Virus_Scan/scanners") == ()


def test_binary_owned_io_and_pe_failure_evidence_are_final_json_visible(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZhello")
    assert read_binary_file_bytes(sample, max_size=2) == b"MZ"
    tags = mark_pe_helper_error("stage902_pe_helper", ValueError("bad pe"))
    assert "binary_final_json_must_record" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "scanner_failure_evidence:binary:stage902_pe_helper" in tags


def test_binary_graph_context_is_scanner_owned_read_only() -> None:
    assert detect_evasion_signals(["process_exec"], node={"edges": ["x"]}) < 1.0
    assert detect_evasion_signals(["process_exec"], node={"edges": []}) >= 0.3
