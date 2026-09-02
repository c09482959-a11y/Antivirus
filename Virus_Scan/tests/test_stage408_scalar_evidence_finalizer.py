from Virus_Scan.publication.json_writer import compact_result_record


def test_scalar_evidence_fields_remain_whole_for_json_audit():
    record = compact_result_record({
        "path": "sample.exe",
        "score": 75,
        "classification": "malicious",
        "tags": ["yara_malware"],
        "evidence_snippets": "YARA: hit rule",
        "yara_hits": "RuleA",
        "fingerprint_evidence": "PE MZ header",
        "embedded_payloads": "embedded_pe_payload",
    })

    assert record["evidence_snippets"] == ["YARA: hit rule"]
    assert record["yara_hits"] == ["RuleA"]
    assert record["fingerprint_evidence"] == ["PE MZ header"]
    assert record["embedded_payloads"] == ["embedded_pe_payload"]


def test_dict_evidence_is_canonical_json_fact_not_key_iteration():
    record = compact_result_record({
        "path": "sample.bin",
        "score": 65,
        "classification": "high_confidence",
        "tags": ["embedded_pe_payload"],
        "evidence_snippets": {"rule": "embedded_pe", "offset": 32},
    })

    assert len(record["evidence_snippets"]) == 1
    assert "embedded_pe" in record["evidence_snippets"][0]
    assert "offset" in record["evidence_snippets"][0]
