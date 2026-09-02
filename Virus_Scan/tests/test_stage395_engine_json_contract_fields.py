from Virus_Scan.publication.json_writer import compact_result_record


def test_compact_result_preserves_engine_routing_json_contract_fields():
    record = {
        "path": "/corpus/RenPyGame/lib/Assembly-CSharp.dat",
        "score": 72,
        "classification": "high_confidence",
        "extension": ".dat",
        "declared_extension": ".dat",
        "sniffed_type": "mono_dotnet_assembly",
        "detected_engine": "renpy",
        "container_engine": "renpy",
        "artifact_engine": "unity",
        "effective_analysis_engine": "unity_dotnet",
        "baseline_key": "engine:renpy",
        "extension_baseline": "artifact:unity:.dll",
        "extension_mismatch": True,
        "cross_engine_artifact": True,
        "sniffed_embedded_types": ["pe_mz", "mono_dotnet_assembly"],
        "tags": ["extension_mismatch", "unity_dotnet"],
        "chains": ["cross_engine_payload"],
        "fingerprint_evidence": ["RenPy container", "Unity DLL artifact"],
        "decoded_evidence_snippets": ["Assembly-CSharp metadata detected"],
        "scan_duration_seconds": 0.25,
        "scheduler_mode": "serial",
    }

    compact = compact_result_record(record)

    assert compact["filename"] == "Assembly-CSharp.dat"
    assert compact["sniffed_file_type"] == "mono_dotnet_assembly"
    assert compact["embedded_payloads"] == ["mono_dotnet_assembly", "pe_mz"]
    assert compact["engine_baseline_key"] == "engine:renpy"
    assert compact["extension_baseline_key"] == "artifact:unity:.dll"
    assert compact["duration_seconds"] == 0.25
    assert compact["timing"] == {"scan_duration_seconds": 0.25}

    context = compact["engine_context"]
    assert context["container_engine"] == "renpy"
    assert context["artifact_engine"] == "unity"
    assert context["effective_analysis_engine"] == "unity_dotnet"
    assert context["declared_extension"] == ".dat"
    assert context["sniffed_file_type"] == "mono_dotnet_assembly"
    assert context["engine_baseline_key"] == "engine:renpy"
    assert context["extension_baseline_key"] == "artifact:unity:.dll"
    assert context["extension_mismatch"] is True
    assert context["cross_engine_artifact"] is True
    assert context["embedded_payloads"] == ["pe_mz", "mono_dotnet_assembly"]
