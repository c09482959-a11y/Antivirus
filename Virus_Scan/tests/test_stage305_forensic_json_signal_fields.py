import json

from Virus_Scan.publication.json_writer import finalize_scan_results


def test_stage305_compact_json_preserves_forensic_signal_fields(tmp_path):
    out = tmp_path / "scan_results.json"
    record = {
        "file": str(tmp_path / "sample.rpyc"),
        "score": 90,
        "class": "malicious",
        "classification": "malicious",
        "tags": ["renpy_pickle_exec", "encoded_powershell", "archive_inner:payload"],
        "chains": ["pickle_execution_chain"],
        "temporal_features": {"belief": 0.8},
        "markov_features": {"transition": 0.7},
        "cluster_features": {"cluster": "suspicious"},
        "graph_features": {"risk": 0.9},
        "yara_hits": ["rule_pickled_exec"],
        "explanation": {"reasons": ["Pickle: confirmed exec", "PowerShell: powershell -enc SQBFAFgA"]},
        "extension": "rpyc",
        "detected_engine": "renpy",
        "scheduler_mode": "serial",
        "scan_duration_seconds": 0.01,
        "errors": [],
        "warnings": [],
    }
    assert finalize_scan_results(str(out), {record["file"]: record})
    data = json.loads(out.read_text())[record["file"]]
    assert data["exit_code"] == 3
    assert data["temporal_signals"] == {"belief": 0.8}
    assert data["markov_sequence_signals"] == {"transition": 0.7}
    assert data["clustering_signals"] == {"cluster": "suspicious"}
    assert data["graph_signals"] == {"risk": 0.9}
    assert data["yara_signals"] == ["rule_pickled_exec"]
    assert "encoded_powershell" in data["entropy_signals"]
    assert "archive_inner:payload" in data["archive_container_signals"]
    assert any("PowerShell:" in item for item in data["decoded_evidence_snippets"])
    assert "crash_traceback" in data
