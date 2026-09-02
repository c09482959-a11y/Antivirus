from __future__ import annotations

import json

from Virus_Scan.models import temporal
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


def test_stage1322_temporal_validation_rejects_non_finite_markov_strength_as_unavailable_evidence() -> None:
    result = temporal.compute_temporal_validation(
        "stage1322-temporal-nonfinite-markov",
        tags=physical_tag_evidence(("certutil_exec", "network_download")),
        prev_stage="asset",
        curr_stage="runtime",
        markov={
            "transition": float("inf"),
            "rarity": 0.0,
            "pair_anomaly": float("nan"),
            "sequence_anomaly": 0.0,
        },
    )

    assert result["evidence_type"] == "temporal_validation"
    assert result["degraded"] is True
    assert result["unavailable_reason"] == "markov_features_invalid"
    assert "temporal_markov_feature_failure_evidence" in result["hits"]
    assert "temporal_markov_high_anomaly" not in result["hits"]
    assert "temporal_markov_anomaly" not in result["hits"]
    json.dumps(result, sort_keys=True, allow_nan=False)


def test_stage1322_temporal_validation_preserves_valid_finite_markov_anomaly() -> None:
    result = temporal.compute_temporal_validation(
        "stage1322-temporal-finite-markov",
        tags=physical_tag_evidence(("certutil_exec", "network_download")),
        prev_stage="asset",
        curr_stage="runtime",
        markov={
            "transition": 0.95,
            "rarity": 0.0,
            "pair_anomaly": 0.0,
            "sequence_anomaly": 0.0,
        },
    )

    assert result["degraded"] is False
    assert "temporal_markov_high_anomaly" in result["hits"]
    json.dumps(result, sort_keys=True, allow_nan=False)
