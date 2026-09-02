from Virus_Scan.publication.json_writer import compact_result_record


def test_compact_result_order_insensitive_audit_fields_are_deterministic():
    base = {
        "file": "payload.bin",
        "score": 80,
        "classification": "high_confidence",
        "tags": ["archive_zip", "entropy_high"],
        "decoded_evidence_snippets": ["Url: https://example.test/payload", "Pickle: reduce exec", "Url: https://example.test/payload"],
        "warnings": ["z diagnostic", "a diagnostic", "z diagnostic"],
        "yara_signals": ["RuleZ", "RuleA", "RuleZ"],
        "entropy_signals": ["packed", "encrypted", "packed"],
        "archive_container_signals": ["zip", "rpa", "zip"],
        "fingerprint_evidence": ["unity dll", "renpy container", "unity dll"],
        "yara_hits": ["HitB", "HitA", "HitB"],
    }
    reordered = dict(base)
    for key in (
        "decoded_evidence_snippets",
        "warnings",
        "yara_signals",
        "entropy_signals",
        "archive_container_signals",
        "fingerprint_evidence",
        "yara_hits",
    ):
        reordered[key] = list(reversed(base[key]))

    first = compact_result_record(base)
    second = compact_result_record(reordered)

    for key in (
        "decoded_evidence_snippets",
        "evidence_snippets",
        "warnings",
        "yara_signals",
        "entropy_signals",
        "archive_container_signals",
        "fingerprint_evidence",
        "yara_hits",
    ):
        assert first[key] == second[key]

    assert first["decoded_evidence_snippets"] == [
        "Pickle: reduce exec",
        "Url: https://example.test/payload",
    ]
