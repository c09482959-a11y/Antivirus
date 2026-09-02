from Virus_Scan.publication.json_writer import compact_result_record


def test_scalar_errors_remain_explicit_error_entries_not_characters():
    record = compact_result_record({
        "path": "bad.rpa",
        "classification": "scan_error",
        "score": 0,
        "errors": "malformed_container_header",
        "warnings": "truncated archive member",
    })

    assert record["errors"] == ["malformed_container_header"]
    assert record["warnings"] == ["truncated archive member"]
    assert record["exit_code"] == 4


def test_scalar_yara_and_archive_signals_remain_single_evidence_values():
    record = compact_result_record({
        "path": "payload.bin",
        "classification": "high_confidence",
        "score": 80,
        "tags": ["embedded_archive"],
        "yara_signals": "Rule.Malware.Test",
        "archive_container_signals": "zip_member_payload",
    })

    assert record["yara_signals"] == ["Rule.Malware.Test"]
    assert record["archive_container_signals"] == ["zip_member_payload"]
