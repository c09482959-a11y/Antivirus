"""Structured scoring explainability ownership.

This module owns the final explanation payload assembly only.  Immutable score
component records and pure component builders live in bounded explainability
submodules so scoring, enrichment, and explainability ownership remain separate.
"""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.detection.scoring.explainability.score_component_builders import (
    as_score_float,
    cap_score_components,
    filetype_context,
    layer_score_components,
    score_component,
)
from Virus_Scan.detection.scoring.explainability.score_component_models import ScoreContribution
from Virus_Scan.detection.models.stage_value_utils import detection_value_or_default, thaw_detection_value


def _explainability_text(value: object, default: str, reason: str) -> tuple[str, str]:
    text, unavailable_reason = no_hook_text(
        value,
        missing_reason="missing_score_explainability_text",
        unsupported_reason=reason,
    )
    if unavailable_reason:
        return default, unavailable_reason
    stripped = text.strip()
    return (stripped or default), ""


def _score_reproducibility_record(
    *, component_count: int, subtotal: float, emitted_score: float
) -> dict[str, object]:
    return {
        "component_count": component_count,
        "component_sum": round(subtotal, 10),
        "emitted_score": round(emitted_score, 10),
        "matches_emitted_score": abs(subtotal - emitted_score) <= 1e-7,
        "formula": "sum(score_components[*].weighted_score) == emitted_score",
    }


def _score_component_schema() -> dict[str, object]:
    return {
        "required_fields": [
            "score_source",
            "weight",
            "evidence_reference",
            "reason",
            "engine_context",
            "filetype_context",
            "confidence_impact",
            "malicious_contribution",
            "suspicious_contribution",
            "benign_contribution",
        ]
    }


def build_reproducible_score_explanation(
    *,
    final_score: object,
    explanation: object,
    path: str,
    active_profile: str,
) -> dict[str, object]:
    """Return explanation with structured components that reproduce final_score."""
    explanation_record = thaw_detection_value(detection_value_or_default(explanation, {}))
    if not isinstance(explanation_record, dict):
        explanation_record = {"unstructured_explanation": explanation_record}

    layers = explanation_record.get("layers")
    if not isinstance(layers, Mapping):
        layers = {}
    weights = explanation_record.get("weights")
    if not isinstance(weights, Mapping):
        weights = {}

    engine_context_value = "other" if active_profile is None or active_profile == "" else active_profile
    engine_context, engine_context_reason = _explainability_text(
        engine_context_value,
        "other",
        "unsafe_score_explainability_engine_context_rejected",
    )
    filetype = filetype_context(path)
    explainability_evidence: list[str] = []
    if engine_context_reason:
        explainability_evidence.append(engine_context_reason)
    component_records = [
        component.to_record()
        for component in layer_score_components(
            layers=layers,
            weights=weights,
            engine_context=engine_context,
            filetype_context_value=filetype,
        )
    ]
    component_records.extend(
        component.to_record()
        for component in cap_score_components(
            caps=detection_value_or_default(explanation_record.get("caps"), ()),
            engine_context=engine_context,
            filetype_context_value=filetype,
        )
    )

    subtotal = sum(as_score_float(component.get("weighted_score")) for component in component_records)
    emitted_score = as_score_float(final_score)
    residual = emitted_score - subtotal
    if abs(residual) > 1e-9 or not component_records:
        component_records.append(
            score_component(
                score_source="reconciliation:score_total",
                weight=1.0,
                raw_score=residual,
                weighted_score=residual,
                evidence_reference=tuple(
                    explainability_evidence
                    + [
                        "active_layers:"
                        + _explainability_text(
                            explanation_record.get("active_layers", 0),
                            "unavailable",
                            "unsafe_score_explainability_active_layers_rejected",
                        )[0],
                        "layer_bonus_anchor_floor_or_cap_reconciliation",
                    ]
                ),
                reason="reconcile structured score components to emitted detection score",
                engine_context=engine_context,
                filetype_context_value=filetype,
            ).to_record()
        )
        subtotal += residual

    explanation_record["score_components"] = component_records
    explanation_record["score_reproducibility"] = _score_reproducibility_record(
        component_count=len(component_records),
        subtotal=subtotal,
        emitted_score=emitted_score,
    )
    if explainability_evidence:
        explanation_record["score_explainability_evidence"] = tuple(explainability_evidence)
    explanation_record["score_component_schema"] = _score_component_schema()
    return explanation_record


__all__ = ("ScoreContribution", "build_reproducible_score_explanation")
