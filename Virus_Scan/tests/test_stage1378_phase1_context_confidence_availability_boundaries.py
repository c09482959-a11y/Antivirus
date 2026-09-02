"""Stage 1378 Phase 1 context-confidence model availability boundaries."""
from __future__ import annotations

from Virus_Scan.detection.scoring.weighting.context_confidence import (
    compute_context_confidence_amplifier,
)
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence



def _context_kwargs() -> dict[str, object]:
    return {
        "node": "sample.exe",
        "tags": physical_tag_evidence(("cmd_exec", "network_download")),
        "pre_context_score": 50.0,
    }


def test_stage1378_unavailable_graph_and_intel_layers_do_not_boost_context() -> None:
    clean = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={"graph": {"score": 100.0}, "intel": {"score": 100.0}},
        adaptive_learning={},
    )
    unavailable = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={
            "graph": {"score": 100.0, "graph_unavailable_reason": "graph_snapshot_unavailable"},
            "intel": {"score": 100.0, "threat_intel_unavailable_reason": "intel_snapshot_unavailable"},
        },
        adaptive_learning={},
    )

    assert clean["applied_bonus"] > 0.0
    assert unavailable["applied_bonus"] == 0.0
    assert unavailable["graph_score"] == 0.0
    assert unavailable["intel_score"] == 0.0
    assert unavailable["context_unavailable_reasons"] == {
        "graph": "graph_snapshot_unavailable",
        "threat_intel": "intel_snapshot_unavailable",
    }
    assert unavailable["hits"] == ["context_no_boost"]


def test_stage1378_degraded_markov_context_signal_does_not_boost_context() -> None:
    clean = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={},
        adaptive_learning={"markov": {"markov_anomaly": 1.0}},
    )
    degraded = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={},
        adaptive_learning={"markov": {"markov_anomaly": 1.0, "degraded": True}},
    )

    assert clean["applied_bonus"] > 0.0
    assert degraded["applied_bonus"] == 0.0
    assert degraded["markov_signal"] == 0.0
    assert degraded["context_unavailable_reasons"] == {
        "markov": "degraded_context_model_signal",
    }
    assert degraded["hits"] == ["context_no_boost"]


def test_stage1378_unavailable_cluster_context_signal_returns_explicit_evidence() -> None:
    result = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={},
        adaptive_learning={
            "cluster": {
                "cluster_id": "cluster-a",
                "cluster_members": 99,
                "cluster_tag_overlap": 1.0,
                "cluster_signal": 1.0,
                "unavailable_reason": "cluster_snapshot_unavailable",
            }
        },
    )

    assert result["applied_bonus"] == 0.0
    assert result["vector_bonus_raw"] == 0.0
    assert result["cluster"]["eligible"] is False
    assert result["cluster"]["unavailable_reason"] == "cluster_snapshot_unavailable"
    assert result["cluster"]["reason"] == "cluster_snapshot_unavailable"


def test_stage1378_nonfinite_context_layer_scores_emit_unavailable_evidence() -> None:
    result = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={
            "graph": {"score": float("inf")},
            "intel": {"score": float("nan")},
        },
        adaptive_learning={},
    )

    assert result["applied_bonus"] == 0.0
    assert result["graph_score"] == 0.0
    assert result["intel_score"] == 0.0
    assert result["context_unavailable_reasons"] == {
        "graph": "non_finite_context_layer_score",
        "threat_intel": "non_finite_context_layer_score",
    }


def test_stage1378_nonfinite_markov_context_signal_emits_unavailable_evidence() -> None:
    result = compute_context_confidence_amplifier(
        **_context_kwargs(),
        layers={},
        adaptive_learning={"markov": {"markov_anomaly": float("inf")}},
    )

    assert result["applied_bonus"] == 0.0
    assert result["markov_signal"] == 0.0
    assert result["context_unavailable_reasons"] == {
        "markov": "non_finite_context_model_signal",
    }
