from __future__ import annotations

from pathlib import Path

import pytest

from Virus_Scan.core import logging as core_logging
from Virus_Scan.orchestration import lifecycle
from Virus_Scan.reporting import evidence_lines, output, result_schema
from Virus_Scan.virustotal import client as virustotal_client
from Virus_Scan.virustotal import reporting as virustotal
from Virus_Scan.virustotal.config import VirusTotalConfig
from Virus_Scan.virustotal.contracts import VirusTotalReportingResult
from Virus_Scan.publication.virustotal_summary import build_virustotal_findings_summary
from Virus_Scan.reporting.evidence_line_text import context_around, raw_sample_text, safe_report_text


def test_stage2085_reporting_text_defaults_are_local_control_states() -> None:
    assert safe_report_text(None) == ""
    assert safe_report_text("alpha\x00\x01 beta", limit=100) == "alpha beta"
    assert context_around("prefix powershell -enc payload suffix", "powershell", radius=4) == "fix powershell -en"
    assert context_around("no match", "powershell") == ""
    assert raw_sample_text({"raw_sample": b"abc\xff"}, "fallback") == "abcÿ"
    assert raw_sample_text({}, "fallback") == "fallback"


def test_stage2085_cli_evidence_line_failure_returns_empty_after_recorded_boundary() -> None:
    original_add_url_lines = evidence_lines.add_url_lines

    def raising_add_url_lines(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise RuntimeError("forced evidence extractor failure")

    try:
        evidence_lines.add_url_lines = raising_add_url_lines
        assert evidence_lines.cli_human_evidence_lines(Path("missing.bin"), {"tags": []}) == []
    finally:
        evidence_lines.add_url_lines = original_add_url_lines


def test_stage2085_reporting_ratio_and_vt_unavailable_states_are_explicit() -> None:
    assert output._decode_printable_ratio(object()) == 0.0
    assert output._decode_printable_ratio(b"") == 0.0
    assert output._decode_printable_ratio(b"ABCD\n") == 1.0
    assert result_schema._decode_printable_ratio(object()) == 0.0
    assert result_schema._decode_printable_ratio(b"ABCD") == 1.0
    vt_summary = build_virustotal_findings_summary(
        scan_id="stage2085",
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
    assert vt_summary.rows == ()
    assert vt_summary.to_record()["projection_policy"]["unknown_is_negative"] is False


def test_stage2085_retryable_file_failure_fails_closed_when_classification_boundary_breaks() -> None:
    original_lower = result_schema._result_schema_lower
    original_record = result_schema._best_effort_record_result_schema_failure
    events: list[str] = []

    def raising_lower(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        raise RuntimeError("forced classification failure")

    def record_failure(context, exc, **kwargs):  # noqa: ANN001, ANN003
        events.append(context)
        return True

    try:
        result_schema._result_schema_lower = raising_lower
        result_schema._best_effort_record_result_schema_failure = record_failure
        assert result_schema._umige_result_is_retryable_file_failure({"class": "clean"}) is True
    finally:
        result_schema._result_schema_lower = original_lower
        result_schema._best_effort_record_result_schema_failure = original_record

    assert events == ["retryable_file_failure_classification_failed"]


def test_stage2085_queue_file_result_false_paths_are_not_successful_publication(tmp_path: Path) -> None:
    claim = tmp_path / "claim.json"
    claim.write_text("{}", encoding="utf-8")
    scanned = tmp_path / "bad.rpyc"
    scanned.write_bytes(b"sample")
    assert result_schema.write_queue_file_result(
        tmp_path,
        claim,
        scanned,
        {"file": str(scanned), "error": "locked", "class": "error", "tags": []},
    ) is True
    final_files = list((tmp_path / "file_results").glob("*.json"))
    assert len(final_files) == 1
    final_files[0].write_text("{}", encoding="utf-8")
    assert result_schema._verify_queue_file_result_final(final_files[0], scanned) is False
    assert not final_files[0].exists()


def test_stage2085_virustotal_defaults_are_explicit_unavailable_states() -> None:
    completed = {
        "data": {
            "attributes": {
                "status": "completed",
                "stats": {"malicious": 0},
                "results": {"engine": {"category": "harmless"}},
            }
        }
    }
    summary_row = {"status": "completed", "malicious": 0, "suspicious": 0}
    assert virustotal._analysis_has_populated_results(completed, summary_row) is True
    assert virustotal._analysis_has_populated_results({}, {"status": "queued"}) is False
    assert virustotal._stats_signature({"malicious": "1", "suspicious": 2})[:2] == (1, 2)
    client = virustotal_client.VirusTotalClient(config=VirusTotalConfig(enabled=True), api_key="test-key")
    assert "test-key" not in repr(client)


def test_stage2085_virustotal_connectivity_probe_is_mandatory_and_bounded() -> None:
    source = Path("Virus_Scan/virustotal/client.py").read_text(encoding="utf-8")
    assert "def probe_connectivity" in source
    assert "VIRUSTOTAL_API_HOST" in source
    assert "except OSError" in source
    assert "pre_network_check" not in source
    with pytest.raises(ValueError, match="virustotal_network_timeout_invalid"):
        virustotal_client.VirusTotalClient.probe_connectivity(0.0)


def test_stage2085_core_and_orchestration_none_returns_are_narrow_local_control_states() -> None:
    err = OSError("busy")
    err.errno = 13
    assert core_logging._safe_os_error_int(err, "errno") == 13
    assert core_logging._safe_os_error_int(object(), "errno") is None
    assert lifecycle._owned_bound_method(object(), "missing") is None
    assert lifecycle._owned_bound_method(object(), object()) is None
