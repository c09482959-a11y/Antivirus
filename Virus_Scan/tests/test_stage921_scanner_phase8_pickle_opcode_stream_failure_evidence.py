from __future__ import annotations

from Virus_Scan.scanners.pickle.opcode_analysis import analyze_pickle_opcode_graph


def test_truncated_pickle_stream_parse_error_emits_failure_evidence():
    summary = analyze_pickle_opcode_graph(b"\x80\x04c")
    assert summary["errors"] >= 1
    assert "pickle_opcode_stream_parse_error" in summary.get("error_tags", [])
    records = summary.get("failure_evidence", [])
    assert records
    assert any(
        rec.get("encoding") == "pickle" and rec.get("failure_evidence")
        for rec in records
    )
