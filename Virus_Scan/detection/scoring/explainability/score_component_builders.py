"""Pure builders for reproducible scoring explanation components."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import PurePath

from Virus_Scan.contracts.no_hook_materialization import (
    materialize_json_no_hook,
    no_hook_finite_float,
    no_hook_json_sort_key,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.detection.scoring.explainability.score_component_models import ScoreContribution


PLR2004N25_0 = 25.0
PLR2004N50_0 = 50.0

ScoreComponentValue = object
ScoreComponentRecord = dict[ScoreComponentValue, ScoreComponentValue]
ScoreComponentMapping = Mapping[str, ScoreComponentValue]
ScoreComponentItems = tuple[tuple[ScoreComponentValue, ScoreComponentValue], ...]


def _value_or_default(value: ScoreComponentValue, default: ScoreComponentValue) -> ScoreComponentValue:
    """Return a fallback only for absent/empty-string values, without truthiness."""
    if value is None:
        return default
    if isinstance(value, str) and value == "":
        return default
    return value


def _score_text(value: ScoreComponentValue, default: str, reason: str) -> tuple[str, str]:
    text, unavailable_reason = no_hook_text(
        value,
        missing_reason="missing_score_component_text",
        unsupported_reason=reason,
    )
    if unavailable_reason:
        return default, unavailable_reason
    stripped = text.strip()
    return (stripped or default), ""


def _score_field_name(field_name: ScoreComponentValue) -> str:
    text, reason = no_hook_text(
        field_name,
        missing_reason="missing_score_component_field",
        unsupported_reason="unsafe_score_component_field_rejected",
    )
    if reason:
        return "unknown"
    stripped = text.strip()
    return stripped or "unknown"


def _score_float(value: ScoreComponentValue, field_name: str) -> tuple[float, str]:
    field = _score_field_name(field_name)
    metric, reason = no_hook_finite_float(
        value,
        default=0.0,
        reason="unsafe_score_component_" + field + "_rejected",
        non_finite_reason="nonfinite_score_component_" + field,
        allow_exact_text=True,
    )
    return metric, reason


def as_score_float(value: ScoreComponentValue) -> float:
    metric, _reason = _score_float(value, "value")
    return metric


def filetype_context(path: str) -> str:
    text, reason = _score_text(_value_or_default(path, ""), "", "unsafe_score_component_path_rejected")
    if reason:
        return "unknown"
    suffix = PurePath(text).suffix.lower()
    return suffix or "unknown"


def _safe_scalar_term(value: ScoreComponentValue, *, unsupported_prefix: str) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_score_component_evidence_value",
        unsupported_reason="unsupported_score_component_evidence_value",
    )
    if reason:
        return unsupported_prefix + ":" + no_hook_type_name(value)
    return text


def _sequence_items(value: ScoreComponentValue) -> tuple[ScoreComponentValue, ...] | None:
    if type(value) is tuple:
        return tuple(value)
    if type(value) is list:
        return tuple(value)
    if type(value) is set:
        return tuple(sorted(set.__iter__(value), key=lambda item: no_hook_json_sort_key(materialize_json_no_hook(item, context="score_component_evidence"))))
    if type(value) is frozenset:
        return tuple(sorted(frozenset.__iter__(value), key=lambda item: no_hook_json_sort_key(materialize_json_no_hook(item, context="score_component_evidence"))))
    return None


def evidence_terms(value: ScoreComponentValue) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (str.__str__(value),)
    if type(value) in (int, float, bool, bytes, bytearray):
        return (_safe_scalar_term(value, unsupported_prefix="unsupported_score_component_evidence_scalar"),)
    mapping_items = no_hook_mapping_items(value)
    if mapping_items is not None:
        terms: list[str] = []
        for index, (key, item) in enumerate(sorted(
            mapping_items,
            key=lambda pair: (
                no_hook_json_sort_key(materialize_json_no_hook(pair[0], context="score_component_evidence_key")),
                no_hook_json_sort_key(materialize_json_no_hook(pair[1], context="score_component_evidence_value")),
            ),
        )):
            key_text = _safe_scalar_term(
                key,
                unsupported_prefix="unsupported_score_component_evidence_key_" + int.__str__(index),
            )
            if type(item) in (str, int, float, bool, bytes, bytearray):
                item_text = _safe_scalar_term(item, unsupported_prefix="unsupported_score_component_evidence_value")
                terms.append(key_text + ":" + item_text)
                continue
            nested_items = _sequence_items(item)
            if nested_items is not None:
                terms.append(key_text + ":" + int.__str__(len(nested_items)))
                continue
            if no_hook_mapping_items(item) is not None:
                terms.append(key_text + ":mapping")
                continue
            if item is not None:
                terms.append(key_text + ":unsupported_score_component_evidence_value:" + no_hook_type_name(item))
        return tuple(terms)
    sequence_items = _sequence_items(value)
    if sequence_items is not None:
        return tuple(
            _safe_scalar_term(item, unsupported_prefix="unsupported_score_component_evidence_item")
            for item in sequence_items
            if item is not None
        )
    return ("unsupported_score_component_evidence_value:" + no_hook_type_name(value),)


def classified_contribution(amount: float) -> tuple[float, float, float]:
    if amount >= PLR2004N50_0:
        return (amount, 0.0, 0.0)
    if amount >= PLR2004N25_0:
        return (0.0, amount, 0.0)
    return (0.0, 0.0, amount)


def score_component(
    *,
    score_source: str,
    weight: ScoreComponentValue,
    raw_score: ScoreComponentValue,
    weighted_score: ScoreComponentValue,
    evidence_reference: ScoreComponentValue,
    reason: ScoreComponentValue,
    engine_context: str,
    filetype_context_value: str,
) -> ScoreContribution:
    weight_value, weight_reason = _score_float(weight, "weight")
    raw_value, raw_reason = _score_float(raw_score, "raw_score")
    weighted, weighted_reason = _score_float(weighted_score, "weighted_score")
    malicious, suspicious, benign = classified_contribution(weighted)
    evidence = list(evidence_terms(evidence_reference))
    evidence.extend(
        rejection_reason
        for rejection_reason in (weight_reason, raw_reason, weighted_reason)
        if rejection_reason
    )
    reason_text, reason_unavailable = _score_text(reason, "score_component_reason_unavailable", "unsafe_score_component_reason_rejected")
    if reason_unavailable:
        evidence.append(reason_unavailable)
    engine_text, engine_unavailable = _score_text(_value_or_default(engine_context, "other"), "other", "unsafe_score_component_engine_context_rejected")
    if engine_unavailable:
        evidence.append(engine_unavailable)
    filetype_text, filetype_unavailable = _score_text(_value_or_default(filetype_context_value, "unknown"), "unknown", "unsafe_score_component_filetype_context_rejected")
    if filetype_unavailable:
        evidence.append(filetype_unavailable)
    source_text, source_unavailable = _score_text(score_source, "score_component_source_unavailable", "unsafe_score_component_source_rejected")
    if source_unavailable:
        evidence.append(source_unavailable)
    return ScoreContribution(
        score_source=source_text,
        weight=weight_value,
        raw_score=raw_value,
        weighted_score=weighted,
        evidence_reference=tuple(evidence),
        reason=reason_text,
        engine_context=engine_text,
        filetype_context=filetype_text,
        confidence_impact=weighted,
        malicious_contribution=malicious,
        suspicious_contribution=suspicious,
        benign_contribution=benign,
    )


def _owned_mapping_items(value: ScoreComponentValue) -> ScoreComponentItems:
    items = no_hook_mapping_items(value)
    return items if items is not None else ()


def layer_score_components(
    *,
    layers: ScoreComponentMapping,
    weights: ScoreComponentMapping,
    engine_context: str,
    filetype_context_value: str,
) -> tuple[ScoreContribution, ...]:
    components: list[ScoreContribution] = []
    weight_items = dict(_owned_mapping_items(weights))
    for layer_name, layer in sorted(
        _owned_mapping_items(layers),
        key=lambda pair: no_hook_json_sort_key(materialize_json_no_hook(pair[0], context="score_layer_name")),
    ):
        layer_items = no_hook_mapping_items(layer)
        if layer_items is None:
            continue
        layer_record = dict(layer_items)
        layer_name_text, _layer_name_reason = _score_text(layer_name, "unsupported_layer_name", "unsafe_score_layer_name_rejected")
        raw_score, raw_reason = _score_float(layer_record.get("score"), "raw_score")
        weight, weight_reason = _score_float(weight_items.get(layer_name), "weight")
        evidence = list(evidence_terms(_value_or_default(layer_record.get("hits"), ())))
        evidence.extend(
            rejection_reason
            for rejection_reason in (raw_reason, weight_reason)
            if rejection_reason
        )
        components.append(
            score_component(
                score_source="layer:" + layer_name_text,
                weight=weight,
                raw_score=raw_score,
                weighted_score=raw_score * weight,
                evidence_reference=tuple(evidence),
                reason=_value_or_default(layer_record.get("name"), layer_name_text),
                engine_context=engine_context,
                filetype_context_value=filetype_context_value,
            )
        )
    return tuple(components)


def cap_score_components(
    *,
    caps: ScoreComponentValue,
    engine_context: str,
    filetype_context_value: str,
) -> tuple[ScoreContribution, ...]:
    components: list[ScoreContribution] = []
    cap_items = _sequence_items(caps)
    if cap_items is None:
        return ()
    for index, cap in enumerate(cap_items):
        cap_entries = no_hook_mapping_items(cap)
        if cap_entries is None:
            continue
        cap_record = dict(cap_entries)
        old_score, old_reason = _score_float(cap_record.get("old_score"), "old_score")
        new_score, new_reason = _score_float(cap_record.get("new_score"), "new_score")
        default_name = "score_cap_" + int.__str__(index)
        name, name_reason = _score_text(_value_or_default(cap_record.get("name"), default_name), default_name, "unsafe_score_cap_name_rejected")
        reason_value = _value_or_default(cap_record.get("reason"), name)
        evidence = list(evidence_terms(cap_record))
        evidence.extend(
            rejection_reason
            for rejection_reason in (old_reason, new_reason, name_reason)
            if rejection_reason
        )
        components.append(
            score_component(
                score_source="cap:" + name,
                weight=1.0,
                raw_score=old_score,
                weighted_score=new_score - old_score,
                evidence_reference=tuple(evidence),
                reason=reason_value,
                engine_context=engine_context,
                filetype_context_value=filetype_context_value,
            )
        )
    return tuple(components)


__all__ = (
    "as_score_float",
    "cap_score_components",
    "filetype_context",
    "layer_score_components",
    "score_component",
)
