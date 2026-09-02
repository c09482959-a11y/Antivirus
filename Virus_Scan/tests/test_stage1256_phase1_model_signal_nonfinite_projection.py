from __future__ import annotations

import json
import math

from Virus_Scan.publication import json_writer
from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1256_nonfinite_model_signal_becomes_explicit_model_failure() -> None:
    compact = compact_result_record(
        {
            "file": "nonfinite-temporal.py",
            "path": "nonfinite-temporal.py",
            "node": "nonfinite-temporal.py",
            "score": 64.0,
            "classification": "high",
            "tags": ["temporal_model_evidence"],
            "temporal_signals": {
                "stage_probability_ready": True,
                "stage_probability": math.nan,
            },
            "markov_sequence_signals": [
                {"pair": ["extract", "execute"], "probability": math.inf}
            ],
            "explanation": {"reasons": ["non-finite model signal should not publish"]},
        }
    )

    assert compact["temporal_signals"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
        "source_field": "temporal_signals",
    }
    assert compact["markov_sequence_signals"] == {
        "model_signal_projection_failed": True,
        "reason": "non_finite_model_signal_value",
        "source_field": "markov_sequence_signals",
    }

    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert evidence["unavailable_reasons"] == {
        "markov_sequence_signals": "non_finite_model_signal_value",
        "temporal_signals": "non_finite_model_signal_value",
    }
    failures = evidence["model_failures"]
    assert {failure["failure_type"] for failure in failures} == {"model_signal_projection_failed"}
    assert {failure["affected_fields"] for failure in failures} == {
        ("temporal_signals",),
        ("markov_sequence_signals",),
    }
    json.dumps(compact, sort_keys=True, allow_nan=False)


def test_stage1256_compact_error_path_also_sanitizes_nonfinite_model_signals() -> None:
    record = json_writer.normalize_compact_result_record(
        {
            "file": "nonfinite-graph.py",
            "path": "nonfinite-graph.py",
            "node": "nonfinite-graph.py",
            "score": 55.0,
            "classification": "medium",
            "graph_signals": {"influence": -math.inf},
            "clustering_signals": {"distance": math.nan},
            "explanation": {"reasons": ["forced compact error"]},
        }
    )

    compact = json_writer.build_compact_error_record(record, RuntimeError("forced compact failure"))

    assert compact["final_status"] == "compact_record_error"
    assert compact["graph_signals"]["model_signal_projection_failed"] is True
    assert compact["clustering_signals"]["model_signal_projection_failed"] is True
    evidence = compact["model_evidence"]
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert {failure["affected_fields"] for failure in evidence["model_failures"]} == {
        ("graph_signals",),
        ("clustering_signals",),
    }
    json.dumps(compact, sort_keys=True, allow_nan=False)
