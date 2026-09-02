from Virus_Scan.publication.json_writer import compact_result_record


def test_stage397_set_shaped_audit_fields_are_canonicalized_without_reordering_sequences():
    record = {
        "path": "/corpus/mixed/Game/asset.dat",
        "score": 68,
        "classification": "high_confidence",
        "extension": ".dat",
        "declared_extension": ".dat",
        "detected_engine": "renpy",
        "container_engine": "renpy",
        "artifact_engine": "unity",
        "sniffed_type": "mono_dotnet_assembly",
        "sniffed_embedded_types": {"pe_mz", "mono_dotnet_assembly"},
        "embedded_payloads": {"mono_dotnet_assembly", "pe_mz"},
        "tags": {"unity_dotnet", "extension_mismatch", "encoded_payload"},
        "chains": {"cross_engine_payload", "decode_execute_chain"},
        "errors": {"scanner_explicit_error:z", "scanner_explicit_error:a"},
        "warnings": {"z warning", "a warning"},
        "temporal_signals": ["second", "first"],
        "markov_sequence_signals": ["load", "decode", "execute"],
        "clustering_signals": {"cluster_b", "cluster_a"},
        "graph_signals": {"edge_b", "edge_a"},
        "secondary_baseline_keys": {"artifact:unity:.dll", "engine:renpy"},
        "blocked_baseline_keys": {"suspicious:mismatch", "malicious:payload"},
    }

    first = compact_result_record(record)
    second = compact_result_record(record)

    assert first == second
    assert first["tags"] == ["encoded_payload", "extension_mismatch", "unity_dotnet"]
    assert first["chains"] == ["cross_engine_payload", "decode_execute_chain"]
    assert first["embedded_payloads"] == ["mono_dotnet_assembly", "pe_mz"]
    assert first["errors"] == ["scanner_explicit_error:a", "scanner_explicit_error:z"]
    assert first["warnings"] == ["a warning", "z warning"]
    assert first["clustering_signals"] == ["cluster_a", "cluster_b"]
    assert first["graph_signals"] == ["edge_a", "edge_b"]
    assert first["temporal_signals"] == ["second", "first"]
    assert first["markov_sequence_signals"] == ["load", "decode", "execute"]
