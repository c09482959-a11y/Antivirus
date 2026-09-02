from __future__ import annotations

import json

from Virus_Scan.publication.json_finalization.signal_projection import signal_summary
from Virus_Scan.publication.json_finalization.streaming import finalize_scan_results


def test_stage1716_missing_model_signal_families_emit_domain_evidence() -> None:
    expected = (
        (("temporal_signals", "temporal_features"), "temporal_support_insufficient"),
        (("markov_sequence_signals", "markov_features"), "markov_support_insufficient"),
        (("clustering_signals", "cluster_features", "clustering_features"), "clustering_unassigned"),
        (("graph_signals", "graph_features"), "graph_unavailable"),
    )

    for keys, reason in expected:
        projected = signal_summary({}, *keys)

        assert projected["model_signal_projection_failed"] is True
        assert projected["reason"] == reason
        assert projected["source_field"] == keys[0]
        json.dumps(projected, sort_keys=True)


def test_stage1716_final_json_missing_model_signals_are_not_empty_dicts(tmp_path) -> None:
    output_path = tmp_path / "scan_results.json"
    results = {
        "sample.bin": {
            "file": "sample.bin",
            "classification": "clean",
            "score": 0.0,
            "tags": [],
        }
    }

    assert finalize_scan_results(str(output_path), results) is True
    published = json.loads(output_path.read_text(encoding="utf-8"))["sample.bin"]
    expected = {
        "temporal_signals": "temporal_support_insufficient",
        "markov_sequence_signals": "markov_support_insufficient",
        "clustering_signals": "clustering_unassigned",
        "graph_signals": "graph_unavailable",
    }
    aliases = {
        "temporal_signals": "temporal",
        "markov_sequence_signals": "markov",
        "clustering_signals": "clustering",
        "graph_signals": "graph",
    }

    for field_name, reason in expected.items():
        evidence = published[field_name]
        assert evidence["model_signal_projection_failed"] is True
        assert evidence["reason"] == reason
        assert evidence["source_field"] == field_name
        assert published[aliases[field_name]] == evidence

    json.dumps(published, sort_keys=True)
