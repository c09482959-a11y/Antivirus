from Virus_Scan.publication.json_writer import compact_result_record


def test_compact_result_chains_are_deterministic_after_worker_merge_order_changes():
    base = {
        "file": "sample.bin",
        "path": "sample.bin",
        "score": 55,
        "classification": "suspicious",
        "tags": ["network_download", "process_exec"],
        "chains": ["z_chain", "a_chain", "z_chain"],
    }
    reordered = dict(base)
    reordered["tags"] = list(reversed(base["tags"]))
    reordered["chains"] = list(reversed(base["chains"]))

    first = compact_result_record(base)
    second = compact_result_record(reordered)

    assert first["tags"] == second["tags"] == ["network_download", "process_exec"]
    assert first["chains"] == second["chains"] == ["a_chain", "z_chain"]


def test_compact_result_preserves_evidence_schema_field_for_clean_records():
    compact = compact_result_record({"file": "clean.bin", "score": 0, "classification": "benign_clean", "tags": []})

    assert "decoded_evidence_snippets" in compact
    assert "evidence_snippets" in compact
    assert compact["evidence_snippets"] == []
