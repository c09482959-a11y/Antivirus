"""Behavioral and probabilistic evidence semantics ownership."""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.contracts.behavior_rarity import rarity_multiplier_from_probability
from Virus_Scan.contracts.yara_hits import (
    YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE,
    normalize_yara_hits,
)
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.tags.heuristics.vocabulary import canonical_reporting_tag
from Virus_Scan.contracts.tag_evidence import evidence_level_for_tag as canonical_evidence_level_for_tag
from Virus_Scan.contracts.tag_evidence_persistence import persisted_tag_observation_count_status
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.profiles.baseline_snapshot import (
    read_extension_baseline_snapshot,
)
from Virus_Scan.detection.profiles.baseline_probability import (
    profile_frequency_context_or_failure_record,
    unavailable_bucket_probability_record,
)
from Virus_Scan.models.contracts.empirical_frequency import empirical_frequency_record
from Virus_Scan.models.profiles.maturity import PROFILE_WARMING_MIN_TRUSTED_SUPPORT
from Virus_Scan.detection.contracts.probability import safe_clamp as probability_safe_clamp
from Virus_Scan.detection.scoring.weighting.policy_constants import (
    CONTEXTUAL_DANGEROUS_ANCHOR_TAGS,
    HIGH_RISK_BUCKETS,
)
from Virus_Scan.detection.tags.heuristics.behavior_buckets import tag_behavior_bucket

ANALYTICAL_EVIDENCE_SCHEMA_VERSION = 1
PROBABILISTIC_SEMANTICS_VERSION = 1
CLUSTER_EMBEDDING_CONFIDENCE_VERSION = 'cluster_embedding_overlay_v1'
TAG_RISK_SCORES = MappingProxyType(dict(detection_registry_value('TAG_RISK_SCORES', {})))
CONFIRMED_API_HINTS = frozenset(detection_registry_value('CONFIRMED_API_HINTS', ()))
HIGH_GATE_SINGLE_ANCHOR_TAGS = frozenset(detection_registry_value('HIGH_GATE_SINGLE_ANCHOR_TAGS', ()))
STRUCTURAL_NOISE_TAGS = frozenset(detection_registry_value('STRUCTURAL_NOISE_TAGS', ()))
CONTEXTUAL_WEAK_NOISE_BUCKETS = frozenset(detection_registry_value('CONTEXTUAL_WEAK_NOISE_BUCKETS', ()))
QUALITY_GATE_VERSION = str(detection_registry_value('QUALITY_GATE_VERSION', 'explainability_quality_gates_v1'))


def _semantic_reason(context: object, suffix: str) -> str:
    if type(context) is str and type(suffix) is str:
        return str.__str__(context) + str.__str__(suffix)
    return "semantic_reason_context_rejected"


def _semantic_prefixed_reason(prefix: object, suffix: str) -> str:
    if type(prefix) is str and type(suffix) is str:
        return str.__str__(prefix) + str.__str__(suffix)
    return "semantic_reason_prefix_rejected"


safe_clamp = probability_safe_clamp


def _semantic_text(value: object, *, missing_reason: str, unsupported_reason: str) -> tuple[str, str]:
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return "", reason
    return str.strip(text).lower(), ""


def _semantic_sequence_texts(value: object, *, context: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if value is None:
        return (), ()
    items = no_hook_sequence_items(value)
    if not items and type(value) not in (tuple, list, set, frozenset, str, bytes, bytearray, int, float, bool):
        if no_hook_mapping_items(value) is None:
            return (), (_semantic_reason(context, "_sequence_rejected"),)
    texts: list[str] = []
    reasons: list[str] = []
    for item in items:
        text, reason = _semantic_text(
            item,
            missing_reason=_semantic_reason("missing_", str.__str__(context) + "_text") if type(context) is str else "missing_semantic_context_text",
            unsupported_reason=_semantic_reason("unsafe_", str.__str__(context) + "_text_rejected") if type(context) is str else "unsafe_semantic_context_text_rejected",
        )
        if reason:
            reasons.append(reason)
            continue
        if text:
            texts.append(text)
    return tuple(texts), tuple(reasons)


def _semantic_number(
    value: object,
    *,
    default: float = 0.0,
    minimum: float = 0.0,
    maximum: float = 1.0,
    reason: str,
    non_finite_reason: str,
) -> tuple[float, str]:
    candidate = default if value is None else value
    metric, metric_reason = no_hook_finite_float(
        candidate,
        default=minimum,
        minimum=minimum,
        maximum=maximum,
        reason=reason,
        non_finite_reason=non_finite_reason,
    )
    if metric_reason:
        return probability_safe_clamp(minimum, minimum, maximum), metric_reason
    return probability_safe_clamp(metric, minimum, maximum), ""


def _owned_mapping_value(value: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default


def _confidence_from_mapping(value: object, *, reason_prefix: str) -> tuple[float, str]:
    if value is None:
        return 0.0, ""
    items = no_hook_mapping_items(value)
    if items is None:
        return 0.0, _semantic_prefixed_reason(reason_prefix, "_mapping_rejected")
    return _semantic_number(
        _owned_mapping_value(value, "confidence", 0.0),
        default=0.0,
        reason=_semantic_prefixed_reason("unsafe_", str.__str__(reason_prefix) + "_confidence_rejected") if type(reason_prefix) is str else "unsafe_semantic_confidence_rejected",
        non_finite_reason=_semantic_prefixed_reason("nonfinite_", str.__str__(reason_prefix) + "_confidence") if type(reason_prefix) is str else "nonfinite_semantic_confidence",
    )


def _confidence_value(value: object) -> tuple[float, str]:
    return _semantic_number(
        value,
        default=0.0,
        reason="unsafe_evidence_confidence_rejected",
        non_finite_reason="nonfinite_evidence_confidence",
    )


def extension_tag_probability(engine: object, file_path: object, tag: object) -> Mapping[str, object]:
    """Return smoothed learned tag probability with support provenance."""
    baseline = read_extension_baseline_snapshot(engine, file_path)
    context, context_failure = profile_frequency_context_or_failure_record(baseline)
    if context_failure is not None:
        return context_failure
    persisted_tag_evidence = _owned_mapping_value(baseline, "tag_evidence", None)
    count, count_reason = persisted_tag_observation_count_status(
        persisted_tag_evidence, tag,
    )
    if count_reason:
        return unavailable_bucket_probability_record(
            count_reason, support=context["support"],
        )
    return empirical_frequency_record(
        count,
        context["support"],
        minimum_support=PROFILE_WARMING_MIN_TRUSTED_SUPPORT,
        maturity=context["maturity"],
        suppression_authority=context["suppression_authority"],
    )

def evidence_level_for_tag(tag: object, strings_blob: object = '', path: object = None, api_calls: object = None, ordered_events: object = None) -> tuple[str, float]:
    """Delegate tag evidence classification to the repository contract owner."""
    return canonical_evidence_level_for_tag(
        tag,
        strings_blob=strings_blob,
        path=path,
        api_calls=api_calls,
        ordered_events=ordered_events,
    )


def tag_effective_evidence_score(engine: object, file_path: object, tag: object, strings_blob: object = '', api_calls: object = None, ordered_events: object = None) -> dict[str, object]:
    tag_text, tag_reason = _semantic_text(
        tag,
        missing_reason="missing_behavior_tag",
        unsupported_reason="unsafe_behavior_tag_rejected",
    )
    if tag_reason:
        return {
            'tag': '',
            'bucket': 'other_behavior',
            'risk': 0.0,
            'risk_raw': 0.0,
            'evidence': 'unavailable',
            'confidence': 0.0,
            'probability': 0.0,
            'rarity_multiplier': 1.0,
            'effective_score': 0.0,
            'score_cap': 0.0,
            'ready': False,
            'reason': tag_reason,
            'failure_evidence_recorded': True,
        }
    bucket = tag_behavior_bucket(tag_text)
    raw_risk = TAG_RISK_SCORES.get(tag_text, 2.0 if bucket == 'other_behavior' else 4.0)
    risk, risk_reason = _semantic_number(
        raw_risk,
        default=2.0 if bucket == 'other_behavior' else 4.0,
        minimum=0.0,
        maximum=100.0,
        reason="unsafe_behavior_risk_rejected",
        non_finite_reason="nonfinite_behavior_risk",
    )
    conf_name, confidence = evidence_level_for_tag(
        tag_text,
        strings_blob=strings_blob,
        path=file_path,
        api_calls=api_calls,
        ordered_events=ordered_events,
    )
    confidence_value, confidence_reason = _confidence_value(confidence)
    probability_record = extension_tag_probability(engine, file_path, tag_text)
    prob = probability_record["probability"]
    rarity = (
        rarity_multiplier_from_probability(
            prob,
            risk=risk,
            bucket=bucket,
            high_risk_names=(
                HIGH_RISK_BUCKETS
                | HIGH_GATE_SINGLE_ANCHOR_TAGS
                | CONTEXTUAL_DANGEROUS_ANCHOR_TAGS
            ),
        )
        if probability_record["ready"] is True
        else 1.0
    )
    raw = risk * confidence_value * rarity
    cap = 2.5 if confidence_value < 0.3 else 5.0 if confidence_value < 0.6 else 10.0
    out = {
        'tag': tag_text,
        'bucket': bucket,
        'risk': probability_safe_clamp(risk / 10.0),
        'risk_raw': risk,
        'evidence': conf_name,
        'confidence': confidence_value,
        'probability': prob,
        'rarity_multiplier': rarity,
        'effective_score': min(raw, cap),
        'score_cap': cap,
        'probability_ready': probability_record["ready"],
        'probability_unavailable_reason': probability_record["reason"],
        'probability_support': probability_record["support"],
    }
    if probability_record.get("final_json_must_record") is True:
        out["degraded"] = True
        out["final_json_must_record"] = True
        out["replay_record_required"] = True
    rejections = tuple(reason for reason in (risk_reason, confidence_reason) if reason)
    if rejections:
        out['input_rejections'] = rejections
        out['failure_evidence_recorded'] = True
    return out


def tag_evidence_provenance_report(tags: object = None, strings_blob: object = '', path: object = None, api_calls: object = None, ordered_events: object = None) -> dict[str, object]:
    """Publish explainability from the immutable canonical evidence bundle."""
    if type(tags) is TagEvidence:
        tag_evidence = tags
        tag_texts = tuple(tag_evidence.tags)
        tag_reasons: tuple[str, ...] = ()
    else:
        tag_texts, tag_reasons = _semantic_sequence_texts(tags, context="behavior_tags")
        tag_evidence = normalize_tag_evidence(
            tag_texts,
            source_detector="behavioral_semantics",
            source_stage="provenance",
        )
    api_texts, api_reasons = _semantic_sequence_texts(api_calls, context="behavior_api_calls")
    event_texts, event_reasons = _semantic_sequence_texts(ordered_events, context="behavior_ordered_events")
    api_text = ' '.join(api_texts)
    event_text = ' '.join(event_texts)
    records = []
    for evidence in tag_evidence.records[:200]:
        raw = evidence.raw_observation_name or evidence.publication_name
        canon = evidence.canonical_tag_id
        try:
            level, conf = evidence_level_for_tag(
                canon, strings_blob=strings_blob, path=path,
                api_calls=api_calls, ordered_events=ordered_events,
            )
        except RECOVERABLE_RUNTIME_ERRORS:
            level, conf = ('unknown', 0.0)
        conf_value, conf_reason = _confidence_value(conf)
        conf_value = max(conf_value, evidence.confidence)
        if raw in event_text or canon in event_text:
            source_class = 'confirmed_timeline'
            conf_value = max(conf_value, 0.85)
        elif any((hint in api_text for hint in CONFIRMED_API_HINTS)) and (
            raw in api_text or canon in api_text or canon in HIGH_GATE_SINGLE_ANCHOR_TAGS
        ):
            source_class = 'confirmed_api'
            conf_value = max(conf_value, 0.7)
        elif evidence.evidence_kind == 'suppression':
            source_class = 'suppression_or_negative'
            conf_value = 0.0
        elif evidence.evidence_kind == 'failure':
            source_class = 'unavailable'
            conf_value = 0.0
        elif canon in STRUCTURAL_NOISE_TAGS:
            source_class = 'structural_noise'
            conf_value = min(conf_value, 0.35)
        elif evidence.evidence_kind == 'normalized':
            source_class = 'normalized_synonym'
        elif evidence.evidence_kind == 'composite':
            source_class = 'composite_inference'
        elif evidence.evidence_kind == 'derived':
            source_class = 'derived_interpretation'
        elif level in {'decoded_string', 'weak_string'}:
            source_class = 'string_or_pattern'
        else:
            source_class = level or 'observed'
        bucket = evidence.behavior_bucket
        high_authority = canon in HIGH_GATE_SINGLE_ANCHOR_TAGS
        record = {
            'tag': evidence.publication_name,
            'canonical_tag': canon,
            'bucket': bucket,
            'source_class': source_class,
            'evidence_level': level,
            'confidence': round(conf_value, 3),
            'high_authority_single_tag': high_authority,
            'suppressible_noise_candidate': (
                canon in STRUCTURAL_NOISE_TAGS or bucket in CONTEXTUAL_WEAK_NOISE_BUCKETS
            ) and (not high_authority),
            'evidence_id': evidence.evidence_id,
            'root_observation_id': evidence.root_observation_id,
            'evidence_kind': evidence.evidence_kind,
            'parent_evidence_ids': evidence.parent_evidence_ids,
            'correlation_group': evidence.correlation_group,
            'polarity': evidence.polarity,
            'scoreability_class': evidence.scoreability_class,
            'attack_phase': evidence.attack_phase,
            'vocabulary_version': evidence.vocabulary_version,
            'rule_version': evidence.rule_version,
            'unavailable_reason': evidence.unavailable_reason,
        }
        if conf_reason:
            record['input_rejections'] = (conf_reason,)
            record['failure_evidence_recorded'] = True
        records.append(record)
    report = {
        'version': QUALITY_GATE_VERSION,
        'tag_evidence_schema_version': tag_evidence.summary.get('schema_version'),
        'tag_evidence_summary': dict(tag_evidence.summary),
        'canonical_tag_evidence': tag_evidence.to_record(record_limit=200),
        'records': records,
    }
    rejections = tuple(tag_reasons + api_reasons + event_reasons)
    if rejections:
        report['input_rejections'] = rejections
        report['failure_evidence_recorded'] = True
    return report


def _semantic_yara_context(yara_hits: object) -> dict[str, object]:
    """Return bounded descriptive YARA context with no scoring authority."""
    hits = tuple(normalize_yara_hits(yara_hits))
    if hits == (YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE,):
        return {
            'confidence': 0.0,
            'hit_count': 0,
            'probability_authority': False,
            'reason': 'behavior_yara_hits_rejected',
            'failure_evidence_recorded': True,
        }
    return {
        'confidence': 0.0,
        'hit_count': len(hits),
        'probability_authority': False,
        'reason': 'yara_production_calibration_unavailable' if hits else '',
    }


def _semantic_evidence_bucket(tag: object) -> str:
    low, reason = _semantic_text(
        tag,
        missing_reason="missing_semantic_bucket_tag",
        unsupported_reason="unsafe_semantic_bucket_tag_rejected",
    )
    if reason:
        return 'other_behavior'
    if low in {'process_exec', 'script_execution', 'cmd_exec', 'powershell_exec', 'shell_exec'} or 'exec' in low:
        return 'os_execution'
    if low in {'network_download', 'network_activity', 'c2_beacon', 'remote_payload_download'} or 'network' in low or 'download' in low or ('c2' in low):
        return 'network'
    if low in {'credential_dump_attempt', 'token_secret_access'} or 'credential' in low or 'token' in low or ('password' in low):
        return 'credential'
    if low in {'service_persistence', 'registry_persistence'} or 'persistence' in low or 'run_key' in low or ('service' in low):
        return 'persistence'
    return 'other_behavior'


def semantic_evidence_vector_overlay(tags: object = None, yara_hits: object = None, oddity: object = None, markov: object = None, graph: object = None, risk: object = 0.0) -> dict[str, object]:
    """Small explainable vector layer beside heuristic clustering.

    This is not a neural replacement. It gives clustering/JSON a stable semantic
    confidence vector that can later feed ANN/density clustering.
    """
    tag_texts, tag_reasons = _semantic_sequence_texts(tags, context="semantic_vector_tags")
    tagset = set(tag_texts)
    yara_ev = _semantic_yara_context(yara_hits)
    buckets = [_semantic_evidence_bucket(t) for t in tag_texts]
    risk_value, risk_reason = _semantic_number(
        risk,
        default=0.0,
        minimum=0.0,
        maximum=100.0,
        reason="unsafe_semantic_vector_risk_rejected",
        non_finite_reason="nonfinite_semantic_vector_risk",
    )
    oddity_conf, oddity_reason = _confidence_from_mapping(oddity, reason_prefix="semantic_oddity")
    markov_conf, markov_reason = _confidence_from_mapping(markov, reason_prefix="semantic_markov")
    graph_conf, graph_reason = _confidence_from_mapping(graph, reason_prefix="semantic_graph")
    vector = {
        'risk': probability_safe_clamp(risk_value / 100.0),
        'yara_confidence': probability_safe_clamp(_owned_mapping_value(yara_ev, 'confidence', 0.0)),
        'oddity_confidence': probability_safe_clamp(oddity_conf),
        'markov_surprise_confidence': probability_safe_clamp(markov_conf),
        'graph_context_confidence': probability_safe_clamp(graph_conf),
        'execution_bucket': 1.0 if 'os_execution' in buckets or tagset & {'process_exec', 'script_execution'} else 0.0,
        'network_bucket': 1.0 if 'network' in buckets or tagset & {'network_download', 'network_activity'} else 0.0,
        'credential_bucket': 1.0 if 'credential' in buckets or tagset & {'credential_dump_attempt', 'token_secret_access'} else 0.0,
        'persistence_bucket': 1.0 if 'persistence' in buckets or tagset & {'service_persistence', 'registry_persistence'} else 0.0,
    }
    density_signal = sum(dict.values(vector)) / max(1, len(vector))
    out = {
        'schema_version': ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        'version': CLUSTER_EMBEDDING_CONFIDENCE_VERSION,
        'evidence_type': 'semantic_evidence_vector',
        'vector': {k: round(v, 4) for k, v in dict.items(vector)},
        'confidence': round(probability_safe_clamp(density_signal), 4),
        'confidence_source': 'explainable_semantic_vector_overlay',
        'yara_context': dict(yara_ev),
        'yara_probability_unavailable_reason': _owned_mapping_value(
            yara_ev, 'reason', 'yara_production_calibration_unavailable'
        ),
    }
    yara_rejection = (
        _owned_mapping_value(yara_ev, 'reason', '')
        if _owned_mapping_value(yara_ev, 'failure_evidence_recorded', False)
        else ''
    )
    rejections = tuple(
        reason
        for reason in (*tag_reasons, yara_rejection, risk_reason, oddity_reason, markov_reason, graph_reason)
        if reason
    )
    if rejections:
        out['input_rejections'] = rejections
        out['failure_evidence_recorded'] = True
    return out


from Virus_Scan.detection.evidence.behavioral.probabilistic_semantics import probabilistic_evidence_semantics, probabilistic_evidence_summary

__all__ = ('evidence_level_for_tag', 'probabilistic_evidence_semantics', 'probabilistic_evidence_summary', 'semantic_evidence_vector_overlay', 'tag_effective_evidence_score', 'tag_evidence_provenance_report')
