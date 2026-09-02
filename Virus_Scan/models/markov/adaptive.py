"""Canonical adaptive projection of learned Markov feature evidence."""
from __future__ import annotations

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.model_feature_bundle import make_model_feature_bundle
from Virus_Scan.models.markov.feature_boundaries import (
    _markov_mapping_float,
    _markov_mapping_int,
    _markov_mapping_is_true,
    _markov_mapping_value,
)
from Virus_Scan.models.markov.features import compute_markov_features
from Virus_Scan.utils.probability import safe_clamp

_ADAPTIVE_MODEL_VERSION = "markov_adaptive_signal_v2_contextual_dirichlet"

def adaptive_markov_signal(prev_stage: object, curr_stage: object, tags: object) -> object:
    """Project every learned Markov anomaly component into adaptive evidence."""
    try:
        mf = compute_markov_features(prev_stage, tags, curr_stage)
        metrics = tuple(
            safe_clamp(_markov_mapping_float(mf, field)[0])
            for field in ("rarity", "transition", "pair_anomaly", "sequence_anomaly")
        )
        strength = safe_clamp(max(metrics) * 0.55 + (sum(metrics) / len(metrics)) * 0.45)
        return make_model_feature_bundle(
            {
                "markov_anomaly": strength,
                "rarity": metrics[0],
                "transition": metrics[1],
                "pair_anomaly": metrics[2],
                "sequence_anomaly": metrics[3],
                "markov_ready": _markov_mapping_is_true(mf, "ready"),
                "markov_unavailable_reason": _markov_mapping_value(mf, "reason", None),
                "markov_support": _markov_mapping_int(mf, "support", 0),
                "markov_confidence": _markov_mapping_float(mf, "confidence")[0],
                "source_model_version": _markov_mapping_value(mf, "model_version", None),
            },
            model_version=_ADAPTIVE_MODEL_VERSION,
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error("adaptive markov signal failed")
        return make_model_feature_bundle(
            {
                "markov_anomaly": 0.0,
                "rarity": 0.0,
                "transition": 0.0,
                "pair_anomaly": 0.0,
                "sequence_anomaly": 0.0,
                "markov_ready": False,
                "markov_unavailable_reason": "markov_signal_failed",
                "markov_support": 0,
                "markov_confidence": 0.0,
                "source_model_version": None,
            },
            model_version=_ADAPTIVE_MODEL_VERSION,
        )


__all__ = ("adaptive_markov_signal",)
