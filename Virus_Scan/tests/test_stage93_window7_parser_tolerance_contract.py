from pathlib import Path

from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from Virus_Scan.scanners import pickle_scan
from Virus_Scan.scanners import archives


def _low(tags):
    return {str(tag).lower() for tag in tags or []}


def test_pickle_opcode_parser_failure_degrades_without_private_patch():
    tags = pickle_scan.pickle_opcode_graph_tags(b"\x80\x04", path="bad.rpyc")
    low = _low(tags)
    assert {
        "scanner_failure",
        "scanner_degraded",
        "scan_incomplete",
        "pickle_opcode_graph_scan_error",
        "scanner_failure_evidence:pickle:pickle_opcode_graph",
    }.issubset(low)


def test_pickle_opcode_exec_chain_still_reports_canonical_finding():
    tags = pickle_scan.pickle_opcode_graph_tags(b'cos\nsystem\n(S"calc"\ntR.', path="bad.rpyc")
    low = _low(tags)
    assert "confirmed_pickle_exec_chain" not in low
    assert "pickle_opcode_execution" not in low
    assert "pickle_reduce_opcode" in low
    assert "pickle_callable_reference" in low
    assert "process_exec" in low
    evidence = evaluate_chain_evidence(tags=physical_tag_evidence(tuple(tags)))
    decision = next(
        item for item in evidence.decisions
        if item.candidate.chain_id == "anchor:pickle_execution_chain"
    )
    assert decision.status == "candidate"


def test_pickle_embedded_payload_member_failure_degrades_without_private_patch():
    tags = pickle_scan.pickle_embedded_payload_tags(b"not empty", path="game.rpyc")
    low = _low(tags)
    assert {
        "scanner_failure",
        "scanner_degraded",
        "scan_incomplete",
        "pickle_payload_opcode_decode_error",
        "scanner_failure_evidence:pickle:pickle_payload_opcode_decode",
    }.issubset(low)


def test_archive_malformed_container_degrades_without_private_patch(tmp_path: Path):
    sample = tmp_path / "broken.zip"
    sample.write_bytes(b"PK\x03\x04bad")
    tags, suspicious = archives.scan_archive_file(str(sample))
    low = _low(tags)
    assert suspicious is True
    assert {
        "scanner_failure",
        "scanner_degraded",
        "scan_incomplete",
        "archive_unsupported_container",
        "scanner_failure_evidence:archive:archive_unsupported_container",
        "archive_final_json_must_record",
    }.issubset(low)


def test_rpa_parse_failure_degrades_without_private_patch(tmp_path: Path):
    sample = tmp_path / "broken.rpa"
    sample.write_bytes(b"RPA-3.0")
    tags, suspicious = archives.scan_rpa_file(str(sample))
    low = _low(tags)
    assert suspicious is True
    assert {
        "scanner_failure",
        "scanner_degraded",
        "scan_incomplete",
        "rpa_failure_evidence_recorded",
        "archive_final_json_must_record",
    }.issubset(low)
