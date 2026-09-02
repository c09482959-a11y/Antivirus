"""Canonical immutable-ready detection result model builders.

These builders own the stable JSON-ready detection result shape used by fast
classification paths.  Callers supply already-classified evidence and scoring
values; this module only assembles the canonical result contract.
"""

from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)


DetectionResultValue = object
DetectionResultMapping = dict[str, DetectionResultValue]
DetectionResultSequence = list[DetectionResultValue]


def _result_unavailable(reason: str, value: DetectionResultValue) -> DetectionResultMapping:
    return {
        "unavailable_reason": reason,
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def _result_text(
    value: DetectionResultValue, default_text: str = "",
) -> str:
    """Detach result text without invoking caller-owned hooks."""
    replacement_text, replacement_reason = no_hook_text(
        default_text,
        missing_reason="missing_result_text_default",
        unsupported_reason="result_text_default_unavailable",
    )
    if replacement_reason:
        replacement_text = ""
    text, reason = no_hook_text(
        value,
        missing_reason="missing_result_text",
        unsupported_reason="result_text_unavailable",
    )
    if reason:
        return replacement_text
    return text


def _result_bool(value: DetectionResultValue, default: bool = False) -> bool:
    """Normalize booleans without leaking hostile truthiness into result contracts."""
    if value is None:
        return default is True
    if type(value) is bool:
        return value
    if type(value) is int and value in (0, 1):
        return value == 1
    text, reason = no_hook_text(
        value,
        missing_reason="missing_result_bool",
        unsupported_reason="result_bool_unavailable",
    )
    if reason == "" and text.strip().lower() in {"true", "1", "yes", "y"}:
        return True
    if reason == "" and text.strip().lower() in {"false", "0", "no", "n"}:
        return False
    return default is True


def _result_float(value: DetectionResultValue, default: float = 0.0) -> float:
    numeric, reason = no_hook_finite_float(
        value,
        default=default,
        reason="result_numeric_unavailable",
        non_finite_reason="result_numeric_nonfinite",
    )
    return numeric if reason == "" else no_hook_finite_float(default, default=0.0)[0]


def _result_sequence(value: DetectionResultValue) -> DetectionResultSequence:
    if value is None:
        return []
    items = no_hook_sequence_items(value)
    if items == ():
        if type(value) in (tuple, list, set, frozenset):
            return []
        return [_result_unavailable("result_sequence_unavailable", value)]
    out = []
    for item in items:
        text, reason = no_hook_text(
            item,
            missing_reason="missing_result_sequence_text",
            unsupported_reason="result_sequence_text_unavailable",
        )
        if reason:
            out.append(_result_unavailable(reason, item))
        elif text != "":
            out.append(text)
    return out


def _result_mapping(value: DetectionResultValue) -> DetectionResultMapping:
    if value is None:
        return {}
    if isinstance(value, dict):
        try:
            items = tuple(dict.items(value))
        except (AttributeError, RuntimeError, TypeError, ValueError):
            items = None
    else:
        items = no_hook_mapping_items(value)
    if items is None:
        return {"model_result_mapping_unavailable": _result_unavailable("result_mapping_unreadable", value)}
    out = {}
    for index, (raw_key, raw_value) in enumerate(items):
        replacement_key = "unavailable_key_" + int.__str__(index)
        key = _result_text(raw_key, default_text=replacement_key)
        if key == "":
            key = replacement_key
        if key in out:
            key = key + "#" + int.__str__(index)
        out[key] = _result_json_value(raw_value)
    return out


def _result_json_value(value: DetectionResultValue) -> DetectionResultValue:
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        return _result_float(value)
    if isinstance(value, str):
        return _result_text(value)
    if type(value) is bytes:
        return _result_text(value)
    if type(value) is bytearray:
        return _result_text(value)
    if isinstance(value, MappingProxyType) or no_hook_mapping_items(value) is not None:
        return _result_mapping(value)
    if type(value) in (list, tuple, set, frozenset):
        return _result_sequence(value)
    return _result_unavailable("result_value_unavailable", value)


def build_fast_benign_detection_result(
    *,
    path: DetectionResultValue,
    score: DetectionResultValue,
    confidence: DetectionResultValue,
    tags: DetectionResultValue,
    prefilter_tags: DetectionResultValue,
    effective_stage: DetectionResultValue,
    reason: DetectionResultValue,
    version: DetectionResultValue,
    constraints: DetectionResultValue,
    model_evidence: DetectionResultValue,
    yaralight_active: DetectionResultValue = False,
) -> DetectionResultMapping:
    score_value = _result_float(score)
    confidence_value = _result_float(confidence)
    path_text = _result_text(path)
    return {
        "node": path_text,
        "file": path_text,
        "score": score_value,
        "cluster": None,
        "class": "benign_clean",
        "classification": "benign_clean",
        "confidence": confidence_value,
        "tags": _result_sequence(tags),
        "prefilter_tags": _result_sequence(prefilter_tags),
        "yara_hits": [],
        "api": {
            "api_calls": [],
            "ngrams": [],
            "call_graph": {},
            "graph_features": {},
            "behavior_timeline": [],
            "ordered_events": [],
        },
        "behavior_timeline": [],
        "ordered_events": [],
        "attack_intelligence": {},
        "heuristics": {"score": 0.0, "hits": []},
        "layered_detection": {},
        "active_layers": 0,
        "layer_weights": {},
        "graph_features": {"risk": 0.0, "base_risk": 0.0, "anomaly": 0.0},
        "temporal_features": {"belief": 0.0},
        "markov_features": {"transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0},
        "engine_context": {"other": 1.0},
        "profile_selection": {"active_profile": "other"},
        "feature_vector": [],
        "model_evidence": _result_mapping(model_evidence),
        "fast_path": True,
        "learn_eligible": False,
        "effective_stage": effective_stage,
        "suspicious_type_router": False,
        "explanation": {
            "classification": "benign_clean",
            "exit_code": 0,
            "reasons": [_result_text(reason)],
            "fast_path": True,
            "learn_eligible": False,
            "version": version,
            "constraints": dict(_result_mapping(constraints), yaralight_active=_result_bool(yaralight_active)),
        },
    }


def build_fast_suspicious_detection_result(
    *,
    path: DetectionResultValue,
    score: DetectionResultValue,
    tags: DetectionResultValue,
    active_profile: DetectionResultValue,
    reason: DetectionResultValue,
    version: DetectionResultValue,
    constraints: DetectionResultValue,
    heuristic_hits: DetectionResultValue,
    confidence: DetectionResultValue,
    attack_hit: DetectionResultValue,
    model_evidence: DetectionResultValue,
) -> DetectionResultMapping:
    score_value = _result_float(score)
    confidence_value = _result_float(confidence)
    path_text = _result_text(path)
    classification = "malicious" if score_value >= 75.0 else "high_confidence_suspicious"
    return {
        "node": path_text,
        "file": path_text,
        "score": score_value,
        "cluster": None,
        "class": classification,
        "classification": classification,
        "confidence": confidence_value,
        "tags": _result_sequence(tags),
        "prefilter_tags": _result_sequence(tags),
        "yara_hits": [],
        "api": {
            "api_calls": [],
            "ngrams": [],
            "call_graph": {},
            "graph_features": {},
            "behavior_timeline": [],
            "ordered_events": [],
        },
        "behavior_timeline": [],
        "ordered_events": [],
        "attack_intelligence": {"ready": False, "unavailable_reason": "fast_path_attack_intelligence_not_evaluated", "hits": _result_sequence([attack_hit])},
        "heuristics": {"score": score_value, "hits": _result_sequence(heuristic_hits)[:16]},
        "layered_detection": {},
        "active_layers": 1,
        "layer_weights": {"explicit_game_engine_chain": score_value},
        "graph_features": {"risk": 0.0, "base_risk": 0.0, "anomaly": 0.0},
        "temporal_features": {"belief": 0.0},
        "markov_features": {"transition": 0.0, "rarity": 0.0, "pair_anomaly": 0.0},
        "engine_context": {},
        "profile_selection": {"active_profile": (_result_text(active_profile, "other") or "other")},
        "feature_vector": [],
        "model_evidence": _result_mapping(model_evidence),
        "fast_path": True,
        "learn_eligible": False,
        "effective_stage": "runtime",
        "suspicious_type_router": True,
        "explanation": {
            "classification": classification,
            "exit_code": 2,
            "reasons": [_result_text(reason)],
            "fast_path": True,
            "learn_eligible": False,
            "version": version,
            "constraints": _result_mapping(constraints),
        },
    }


__all__ = ("build_fast_benign_detection_result", "build_fast_suspicious_detection_result")
