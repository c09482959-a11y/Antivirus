from Virus_Scan.tests.support.artifact_read_fixtures import artifact_read_snapshot_fixture

from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.detection.enrichment.pe_analysis.binary_static import scan_binary
from Virus_Scan.scanners.binary_embedded_pickle import scan_binary_embedded_pickle_payloads


def test_detection_binary_static_no_longer_imports_scanner_pickle_contracts():
    source = read_python_file(Path("Virus_Scan/detection/enrichment/pe_analysis/binary_static.py"))
    assert "Virus_Scan.scanners" not in source
    assert "pickle_embedded_payload_tags" not in source


def test_binary_embedded_pickle_observation_stays_scanner_owned(tmp_path):
    sample = tmp_path / "sample.rpyc"
    sample.write_bytes(b"MZ\x00\x00prefix \x80\x04cos\nsystem\n(S'calc'\ntR. suffix")

    tags = set(scan_binary_embedded_pickle_payloads(sample, artifact_read_snapshot=artifact_read_snapshot_fixture(sample)))

    assert "pickle_reduce_opcode" in tags
    assert "pickle_callable_reference" in tags
    assert "pickle_opcode_execution" not in tags
    assert "confirmed_pickle_exec_chain" not in tags
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(sorted(tags))))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:pickle_execution_chain"
    )
    assert decision.status == "blocked"
    assert decision.candidate.blocked_reason == "forbidden_evidence:failure"
    assert decision.scoreable is False


def test_binary_route_uses_scanner_collector_for_embedded_pickle_boundary():
    handler_source = read_python_file(Path("Virus_Scan/routing/extension_scan_handlers.py"))
    router_source = read_python_file(Path("Virus_Scan/routing/extension_scan_router.py"))
    assert "route_binary_stage" in router_source
    assert "scan_binary_embedded_pickle_payloads" in handler_source
    assert "binary_embedded_pickle_raw" in handler_source


def test_detection_binary_static_missing_path_records_degraded_failure_evidence(tmp_path):
    tags = set(scan_binary(tmp_path / "missing.exe", artifact_read_snapshot=artifact_read_snapshot_fixture(tmp_path / "missing.exe"), finalize=False))

    assert "detection_failure_evidence" in tags
    assert "failure_evidence_recorded" in tags
    assert "binary_static_scan_degraded" in tags
    assert "binary_static_scan_binary_input_unavailable" in tags


def test_detection_binary_static_empty_file_records_degraded_failure_evidence(tmp_path):
    sample = tmp_path / "empty.exe"
    sample.write_bytes(b"")

    tags = set(scan_binary(sample, artifact_read_snapshot=artifact_read_snapshot_fixture(sample), finalize=False))

    assert "detection_failure_evidence" in tags
    assert "failure_evidence_recorded" in tags
    assert "binary_static_scan_degraded" in tags
    assert "binary_static_scan_binary_input_empty" in tags
