"""Canonical detection-owned context confidence scoring helpers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.detection.scoring.weighting.policy_constants import (
    COMBINED_CONTEXT_MAX_BONUS,
    CONTEXT_AMPLIFIER_VERSION,
    CONTEXT_CORROBORATION_MAX_BONUS,
    MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST,
    MIN_SCORE_FOR_CONTEXT_BOOST,
    VECTOR_CLUSTER_MAX_BONUS,
)
from Virus_Scan.detection.scoring.weighting.scoreable_tags import (
    concrete_score_count,
    scoreable_tag_evidence,
)
from Virus_Scan.detection.scoring.adaptive.feature_bundle import (
    MIN_CLUSTER_MEMBERS_FOR_CONTEXT,
    MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT,
    model_context_cluster_quality,
)


ContextValue = object
ContextSequence = Sequence[ContextValue]
ContextMapping = Mapping[ContextValue, ContextValue]
MutableContextMapping = dict[ContextValue, ContextValue]
ContextScoreStatus = tuple[float, str | None]


def _optional_iterable(value: ContextValue | None) -> tuple[ContextValue, ...]:
    """Return an optional iterable without probing caller-owned truthiness."""
    return () if value is None else no_hook_sequence_items(value)


def _mapping_or_empty(value: ContextValue) -> MutableContextMapping:
    """Detach a mapping boundary without caller-owned mapping hooks."""
    items = no_hook_mapping_items(value)
    if items is None:
        return {}
    return {key: item for key, item in items}


def _mapping_snapshot_or_none(value: ContextValue) -> MutableContextMapping | None:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    snapshot = {}
    for key, item in items:
        snapshot[key] = item
    return snapshot


def _ctx_probability(value: ContextValue) -> float:
    return safe_clamp(_ctx_float(value, 0.0))


def _ctx_score(value: ContextValue) -> float:
    return safe_clamp(_ctx_float(value, 0.0), 0.0, 100.0)


def _ctx_bonus(value: ContextValue) -> float:
    return safe_clamp(_ctx_float(value, 0.0), 0.0, COMBINED_CONTEXT_MAX_BONUS)


def _bonus_hit(prefix: str, bonus: ContextValue, maximum: float) -> str:
    bounded = min(_ctx_float(bonus, 0.0), maximum)
    return prefix + format(bounded, ".2f")


def _metadata_truthy(value: ContextValue | None) -> bool:
    """Evaluate model metadata flags without invoking hostile hooks."""
    if value is None:
        return False
    if type(value) is bool:
        return value
    text, reason = no_hook_text(
        value,
        missing_reason='missing_context_metadata_flag',
        unsupported_reason='unsafe_context_metadata_flag_rejected',
    )
    if reason:
        return True
    return text.strip().lower() not in ('', '0', 'false', 'none')


def _first_nonempty_mapping(source: ContextValue, *keys: str) -> MutableContextMapping:
    """Return the first present owned mapping among aliases without hooks."""
    source_items = no_hook_mapping_items(source)
    if source_items is None:
        return {}
    source_map = dict(source_items)
    for key in keys:
        value = dict.get(source_map, key)
        items = no_hook_mapping_items(value)
        if items:
            return {item_key: item_value for item_key, item_value in items}
    return {}

def _ctx_float(value: ContextValue, default: float = 0.0) -> float:
    numeric, _reason = no_hook_finite_float(
        value,
        default=default,
        reason='invalid_context_numeric',
        non_finite_reason='non_finite_context_numeric',
    )
    return numeric



def _context_unavailable_reason(record: ContextValue, *specific_keys: str) -> str | None:
    """Return layer/model unavailability metadata before score consumption.

    Context confidence is output-affecting model evidence. A high graph,
    intelligence, or Markov score paired with degraded/unavailable metadata must
    not create a graph/threat/Markov context boost.
    """
    record_map = _mapping_snapshot_or_none(record)
    if record_map is None:
        return None
    for key in (
        'unavailable_reason',
        'failure_reason',
        'error_reason',
        'reason',
        'graph_unavailable_reason',
        'graph_model_unavailable_reason',
        'threat_intel_unavailable_reason',
        'attack_intelligence_unavailable_reason',
        'markov_unavailable_reason',
        'profile_unavailable_reason',
        'cluster_unavailable_reason',
        *specific_keys,
    ):
        value = dict.get(record_map, key)
        if value is not None:
            text, text_reason = no_hook_text(
                value,
                missing_reason='missing_context_unavailable_reason',
                unsupported_reason='unsafe_context_reason_value_rejected',
            )
            if text_reason:
                return text_reason
            text = text.strip()
            if text:
                return text
    if _metadata_truthy(dict.get(record_map, 'degraded')):
        return 'degraded_context_model_signal'
    if _metadata_truthy(dict.get(record_map, 'confidence_degraded')):
        return 'confidence_degraded_context_model_signal'
    return None


def _available_context_score(record: ContextValue, *reason_keys: str) -> ContextScoreStatus:
    reason = _context_unavailable_reason(record, *reason_keys)
    if reason:
        return 0.0, reason
    record_map = _mapping_snapshot_or_none(record)
    if record_map is None:
        return 0.0, None
    score, score_reason = no_hook_finite_float(
        dict.get(record_map, 'score', 0.0),
        default=0.0,
        reason='invalid_context_layer_score',
        non_finite_reason='non_finite_context_layer_score',
    )
    return (score, score_reason or None)


def _available_context_model_signal(record: ContextValue, key: str) -> ContextScoreStatus:
    reason = _context_unavailable_reason(record)
    if reason:
        return 0.0, reason
    record_map = _mapping_snapshot_or_none(record)
    if record_map is None:
        return 0.0, None
    signal, signal_reason = no_hook_finite_float(
        dict.get(record_map, key, 0.0),
        default=0.0,
        reason='invalid_context_model_signal',
        non_finite_reason='non_finite_context_model_signal',
    )
    if signal_reason:
        return 0.0, signal_reason
    clamped_signal = _ctx_probability(signal)
    return clamped_signal, None




_CONTEXT_EVIDENCE_KINDS = frozenset({"observed", "normalized", "derived", "composite"})


def _context_tag_evidence(tags: ContextValue) -> TagEvidence:
    source = tags if type(tags) is TagEvidence else _optional_iterable(tags)
    return scoreable_tag_evidence(source, allowed_evidence_kinds=_CONTEXT_EVIDENCE_KINDS)


def _context_evidence_count(tags: ContextValue) -> int:
    return concrete_score_count(_context_tag_evidence(tags))


def _apply_context_safety_cap_count(
    final_score: float, pre_context_score: float, concrete_count: int,
) -> float:
    if pre_context_score < 25.0:
        return min(final_score, max(pre_context_score, 30.0))
    if concrete_count < 2:
        return min(final_score, max(pre_context_score, 49.0))
    if concrete_count < 3:
        return min(final_score, max(pre_context_score, 74.0))
    return _ctx_score(final_score)


def _cap_context_bonus_count(
    base_score: float, vector_bonus: float, corroboration_bonus: float, concrete_count: int,
) -> float:
    if base_score < MIN_SCORE_FOR_CONTEXT_BOOST:
        return 0.0
    vector_bonus = max(0.0, min(vector_bonus, VECTOR_CLUSTER_MAX_BONUS))
    corroboration_bonus = max(0.0, min(corroboration_bonus, CONTEXT_CORROBORATION_MAX_BONUS))
    if concrete_count < MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST:
        vector_bonus = min(vector_bonus, 3.0)
        corroboration_bonus = min(corroboration_bonus, 4.0)
    combined_cap = 10.0 if base_score < 50.0 else 15.0 if base_score < 75.0 else 8.0
    return min(vector_bonus + corroboration_bonus, combined_cap, COMBINED_CONTEXT_MAX_BONUS)

def apply_context_safety_cap(
    final_score: ContextValue, pre_context_score: ContextValue, concrete_tags: ContextValue,
) -> float:
    """Prevent context alone from crossing major verdict thresholds."""
    return _apply_context_safety_cap_count(
        _ctx_float(final_score, 0.0), _ctx_float(pre_context_score, 0.0),
        _context_evidence_count(concrete_tags),
    )


def cap_context_bonus(
    base_score: ContextValue, vector_bonus: ContextValue, corroboration_bonus: ContextValue,
    concrete_tags: ContextValue,
) -> float:
    """Cap context amplification using distinct canonical evidence roots."""
    return _cap_context_bonus_count(
        _ctx_float(base_score, 0.0), _ctx_float(vector_bonus, 0.0),
        _ctx_float(corroboration_bonus, 0.0), _context_evidence_count(concrete_tags),
    )


def compute_context_confidence_amplifier(
    node: ContextValue, tags: ContextValue, layers: ContextValue,
    adaptive_learning: ContextValue | None = None, pre_context_score: ContextValue = 0.0,
) -> MutableContextMapping:
    """
    Capped confidence amplifier using existing vector clustering and graph/threat-intel-like context.

    Design guarantees:
    - requires a non-clean base score before any boost
    - vector cluster must be mature and tag-overlapping
    - graph/threat/Markov boost is based on existing graph/threat/Markov corroboration
    - context cannot push weak evidence across high-confidence/malicious bands
    """
    tag_evidence = _context_tag_evidence(tags)
    concrete_count = concrete_score_count(tag_evidence)
    layers = _mapping_or_empty(layers)
    adaptive_learning = _mapping_or_empty(adaptive_learning)
    pre_context_score = _ctx_float(pre_context_score, 0.0)
    cluster_quality = model_context_cluster_quality(
        node, tag_evidence, adaptive_learning=adaptive_learning,
    )
    vector_bonus = 0.0
    cluster_quality_map = _mapping_or_empty(cluster_quality)
    if dict.get(cluster_quality_map, 'eligible'):
        cluster_probability = _ctx_probability(dict.get(cluster_quality_map, 'cluster_quality', 0.0))
        vector_bonus = VECTOR_CLUSTER_MAX_BONUS * cluster_probability
    graph_layer = _first_nonempty_mapping(layers, 'graph', 'layer_3_graph_score')
    intel_layer = _first_nonempty_mapping(layers, 'intel', 'layer_4_threat_intelligence')
    graph_score, graph_unavailable_reason = _available_context_score(
        graph_layer,
        'graph_unavailable_reason',
        'graph_model_unavailable_reason',
    )
    intel_score, intel_unavailable_reason = _available_context_score(
        intel_layer,
        'threat_intel_unavailable_reason',
        'attack_intelligence_unavailable_reason',
    )
    markov_meta = _first_nonempty_mapping(adaptive_learning, 'markov')
    markov_signal, markov_unavailable_reason = _available_context_model_signal(markov_meta, 'markov_anomaly')
    graph_signal = _ctx_probability(graph_score / 100.0)
    intel_signal = _ctx_probability(intel_score / 100.0)
    corroboration_signal = graph_signal * 0.5 + intel_signal * 0.3 + markov_signal * 0.2
    corroboration = _ctx_probability(corroboration_signal)
    corroboration_bonus = CONTEXT_CORROBORATION_MAX_BONUS * corroboration
    raw_context_bonus = max(0.0, vector_bonus) + max(0.0, corroboration_bonus)
    capped_bonus = _cap_context_bonus_count(
        pre_context_score, vector_bonus, corroboration_bonus, concrete_count,
    )
    final_after_context = _apply_context_safety_cap_count(
        pre_context_score + capped_bonus, pre_context_score, concrete_count,
    )
    applied_bonus = _ctx_bonus(final_after_context - pre_context_score)
    hits = []
    if applied_bonus > 0.0:
        if vector_bonus > 0.0:
            hits.append(_bonus_hit('context_vector_cluster:+', vector_bonus, VECTOR_CLUSTER_MAX_BONUS))
        if corroboration_bonus > 0.0:
            hits.append(_bonus_hit('context_model_corroboration:+', corroboration_bonus, CONTEXT_CORROBORATION_MAX_BONUS))
        if applied_bonus < raw_context_bonus:
            hits.append('context_bonus_capped')
    else:
        hits.append('context_no_boost')
    return {
        'version': CONTEXT_AMPLIFIER_VERSION,
        'pre_context_score': pre_context_score,
        'post_context_score': final_after_context,
        'applied_bonus': applied_bonus,
        'raw_context_bonus': raw_context_bonus,
        'vector_bonus_raw': vector_bonus,
        'context_corroboration_bonus_raw': corroboration_bonus,
        'combined_context_cap': COMBINED_CONTEXT_MAX_BONUS,
        'concrete_scoreable_evidence_count': concrete_count,
        'cluster': cluster_quality,
        'graph_score': graph_score,
        'intel_score': intel_score,
        'markov_signal': markov_signal,
        'context_unavailable_reasons': {
            key: reason
            for key, reason in (
                ('graph', graph_unavailable_reason),
                ('threat_intel', intel_unavailable_reason),
                ('markov', markov_unavailable_reason),
            )
            if reason
        },
        'hits': hits,
        'caps': {
            'vector_cluster_max_bonus': VECTOR_CLUSTER_MAX_BONUS,
            'context_corroboration_max_bonus': CONTEXT_CORROBORATION_MAX_BONUS,
            'combined_context_max_bonus': COMBINED_CONTEXT_MAX_BONUS,
            'min_concrete_tags_for_context_boost': MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST,
            'min_cluster_members': MIN_CLUSTER_MEMBERS_FOR_CONTEXT,
            'min_cluster_tag_overlap': MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT,
            'min_score_for_context_boost': MIN_SCORE_FOR_CONTEXT_BOOST,
        },
    }


__all__ = (
    'apply_context_safety_cap',
    'cap_context_bonus',
    'compute_context_confidence_amplifier',
)
