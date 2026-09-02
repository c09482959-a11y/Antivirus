from __future__ import annotations

import json
import math

from Virus_Scan.publication.json_writer import compact_result_record


def test_stage1255_existing_model_evidence_nonfinite_float_becomes_canonical_failure() -> None:
    compact = compact_result_record(
        {
            "file": "existing-model-evidence.py",
            "path": "existing-model-evidence.py",
            "node": "existing-model-evidence.py",
            "score": 44.0,
            "classification": "medium",
            "tags": ["model_failure_evidence"],
            "model_evidence": {
                "writer_version": "upstream_model_evidence_v1",
                "feature_probabilities": {"markov": math.nan},
                "final_json_must_record": True,
            },
            "explanation": {"reasons": ["pre-existing model evidence"]},
        }
    )

    evidence = compact["model_evidence"]
    assert evidence["writer_version"] == "upstream_model_evidence_v1"
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    assert "feature_probabilities" not in evidence
    assert evidence["unavailable_reasons"]["markov"] == "non_finite_probability"
    assert evidence["unavailable_reasons"]["model_evidence.feature_probabilities.markov"] == "non_finite_probability"
    failures = evidence["model_failures"]
    assert any(
        failure["failure_type"] == "invalid_model_probability"
        and failure["reason"] == "non_finite_probability"
        for failure in failures
    )
    json.dumps(evidence, sort_keys=True, allow_nan=False)
