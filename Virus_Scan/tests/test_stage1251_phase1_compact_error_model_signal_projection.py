from __future__ import annotations

import json

from Virus_Scan.publication import json_writer


def test_stage1251_compact_error_preserves_existing_model_signals() -> None:
    record = json_writer.normalize_compact_result_record(
        {
            "path": "model-signal-error.py",
            "score": 71.0,
            "classification": "high",
            "tags": ["temporal_anomaly", "graph_influence"],
            "temporal_signals": {"probability_ready": False, "cold_start_reason": "missing_snapshot"},
            "markov_sequence_signals": [{"pair": ["extract", "execute"], "probability": 0.25}],
            "clustering_signals": {"cluster_id": "cold_start", "assigned": False},
            "graph_signals": {"relationship_count": 2, "influence": 0.4},
            "decoded_evidence_snippets": ["decoded payload marker"],
            "explanation": {"reasons": ["model evidence present before finalization error"]},
        }
    )

    compact = json_writer.build_compact_error_record(record, RuntimeError("forced compact failure"))

    assert compact["final_status"] == "compact_record_error"
    assert compact["temporal_signals"] == {"cold_start_reason": "missing_snapshot", "probability_ready": False}
    assert compact["temporal"] == compact["temporal_signals"]
    assert compact["markov_sequence_signals"] == [{"pair": ["extract", "execute"], "probability": 0.25}]
    assert compact["markov"] == compact["markov_sequence_signals"]
    assert compact["clustering_signals"] == {"assigned": False, "cluster_id": "cold_start"}
    assert compact["graph_signals"] == {"influence": 0.4, "relationship_count": 2}
    presence = compact["contextual_signal_frame"]["signal_presence"]
    assert presence["temporal_signals"] is True
    assert presence["markov_sequence_signals"] is True
    assert presence["clustering_signals"] is True
    assert presence["graph_signals"] is True
    json.dumps(compact, sort_keys=True)
