from Virus_Scan.publication.json_writer import compact_result_record


def test_medium_verdict_has_general_evidence_snippets_when_only_reason_exists():
    record = compact_result_record(
        {
            "path": "sample.zip",
            "score": 25,
            "classification": "low_confidence",
            "tags": ["archive_member_graph", "polyglot_artifact"],
            "explanation": {"reasons": ["archive_member_graph"], "classification": "low_confidence"},
        }
    )

    assert record["decoded_evidence_snippets"] == []
    assert record["evidence_snippets"] == ["archive_member_graph"]
    assert record["exit_code"] == 1


def test_medium_verdict_has_tag_evidence_when_reason_is_absent():
    record = compact_result_record(
        {
            "path": "payload.png",
            "score": 35,
            "classification": "high_confidence",
            "tags": ["file_seen", "embedded_pe_payload", "polyglot_artifact"],
            "explanation": {"reasons": [], "classification": "high_confidence"},
        }
    )

    assert "embedded_pe_payload" in record["evidence_snippets"]
    assert "polyglot_artifact" in record["evidence_snippets"]
