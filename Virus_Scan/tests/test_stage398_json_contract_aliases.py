from Virus_Scan.publication.json_writer import compact_result_record


def test_stage398_compact_record_exposes_required_json_audit_aliases():
    record = compact_result_record({
        "path": "sample.bin",
        "file": "sample.bin",
        "score": 25,
        "classification": "low_confidence",
        "tags": ["embedded_pe_payload", "archive_file"],
        "chains": ["download_execute_chain"],
        "yara_signals": ["rule:test"],
        "entropy_signals": ["entropy_high"],
        "temporal_signals": {"burst": 1},
        "markov_sequence_signals": {"rarity": 0.5},
        "clustering_signals": {"cluster": "rare"},
        "graph_signals": {"edges": 2},
        "decoded_evidence_snippets": ["MZ payload"],
        "scan_duration_seconds": 1.25,
    })
    for key in ("yara", "entropy", "temporal", "markov", "clustering", "graph", "duration"):
        assert key in record
    assert record["yara"] == ["rule:test"]
    assert record["entropy"] == ["entropy_high"]
    assert record["temporal"] == {"burst": 1}
    assert record["markov"] == {"rarity": 0.5}
    assert record["clustering"] == {"cluster": "rare"}
    assert record["graph"] == {"edges": 2}
    assert record["duration"] == 1.25
