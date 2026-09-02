from __future__ import annotations

import json

from Virus_Scan.contracts.probabilistic_evidence import (
    correlation_group_summary,
    probabilistic_evidence_summary,
)
from Virus_Scan.reporting.summary import probabilistic_evidence_summary as reporting_summary


def test_stage1318_nonfinite_probability_evidence_cannot_promote_to_confident_group() -> None:
    groups = correlation_group_summary(
        [
            {"correlation_group": "model", "confidence": float("nan")},
            {"correlation_group": "model", "posterior": float("inf")},
        ]
    )

    assert groups["model"]["strongest"] == 0.0
    assert groups["model"]["correlated_fused"] == 0.0
    assert groups["model"]["valid_count"] == 0
    assert groups["model"]["invalid_numeric_inputs"] == 2
    assert groups["model"]["invalid_numeric_reason"] == "non_finite_probability_evidence"
    json.dumps(groups, allow_nan=False)


def test_stage1318_only_nonfinite_probability_evidence_is_explicitly_unavailable() -> None:
    summary = probabilistic_evidence_summary(
        [{"correlation_group": "model", "confidence": float("nan")}]
    )

    assert summary["ready"] is False
    assert summary["posterior"] == 0.0
    assert summary["raw_noisy_or"] == 0.0
    assert summary["reason"] == "no_valid_probability_evidence"
    assert summary["degraded"] is True
    assert summary["failure_evidence_recorded"] is True
    assert summary["invalid_numeric_inputs"] == 1
    json.dumps(summary, allow_nan=False)


def test_stage1318_mixed_probability_evidence_uses_valid_inputs_and_records_degradation() -> None:
    summary = probabilistic_evidence_summary(
        [
            {"correlation_group": "model", "confidence": float("nan")},
            {"correlation_group": "model", "confidence": 0.4},
        ],
        prior=float("inf"),
    )

    assert summary["ready"] is True
    assert 0.0 < summary["posterior"] <= 1.0
    assert summary["degraded"] is True
    assert summary["invalid_numeric_inputs"] == 1
    assert summary["prior_unavailable_reason"] == "non_finite_probability_evidence"
    assert summary["correlation_groups"]["model"]["valid_count"] == 1
    json.dumps(summary, allow_nan=False)


def test_stage1318_reporting_public_summary_uses_hardened_probabilistic_contract() -> None:
    summary = reporting_summary(
        [{"correlation_group": "model", "confidence": float("nan")}]
    )

    assert summary["ready"] is False
    assert summary["posterior"] == 0.0
    assert summary["degraded"] is True
    json.dumps(summary, allow_nan=False)
