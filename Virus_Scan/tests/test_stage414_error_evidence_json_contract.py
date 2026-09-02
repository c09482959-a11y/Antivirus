from Virus_Scan.publication.json_writer import compact_result_record


def test_scalar_error_is_preserved_in_compact_json_errors_and_evidence():
    record = compact_result_record(
        {
            "path": "bad.bin",
            "score": 0,
            "classification": "scan_error",
            "error": "read failed",
            "tags": ["scanner_error"],
        }
    )

    assert record["exit_code"] == 4
    assert record["errors"] == ["read failed"]
    assert record["evidence_snippets"]
    assert "read failed" in record["evidence_snippets"][0]


def test_detector_errors_merge_with_errors_without_character_splitting():
    record = compact_result_record(
        {
            "path": "detector.bin",
            "score": 0,
            "classification": "scan_error",
            "errors": ["outer failure"],
            "detector_errors": "inner detector failure",
            "tags": ["scanner_error"],
        }
    )

    assert record["exit_code"] == 4
    assert record["errors"] == ["outer failure", "inner detector failure"]
