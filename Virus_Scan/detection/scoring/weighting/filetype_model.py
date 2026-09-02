"""Canonical score ownership for filetype bucket model signals."""

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_sequence_items
from Virus_Scan.contracts.tag_evidence import distinct_root_tag_evidence_records, evidence_level_for_tag
from Virus_Scan.detection.contracts.filetype_context import NON_EXECUTION_CAPABILITIES, filetype_validation_context
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.policy_constants import HIGH_RISK_BUCKETS
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.tags.heuristics.behavior_buckets import tag_score_bucket

_FILETYPE_EVIDENCE_KINDS = frozenset({"observed", "normalized", "derived", "composite"})


def filetype_mapping_get(mapping: object, key: object, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and item_key == key:
            return item_value
    return default


def filetype_anomaly_probability(score: object, root_count: object) -> object:
    return safe_clamp(score / max(1, root_count), 0.0, 1.0)


def filetype_text_set(values: object) -> object:
    return {value for value in no_hook_sequence_items(values) if type(value) is str}


def _filetype_tag_evidence(tags: object) -> tuple[TagEvidence, tuple[object, ...]]:
    evidence = scoreable_tag_evidence(tags, allowed_evidence_kinds=_FILETYPE_EVIDENCE_KINDS)
    records = distinct_root_tag_evidence_records(
        evidence.records, allowed_evidence_kinds=_FILETYPE_EVIDENCE_KINDS,
    )
    return evidence, records


def filetype_bucket_model_signal(
    engine: object,
    file_path: object,
    tags: object,
    strings_blob: object = "",
    api_calls: object = None,
    ordered_events: object = None,
) -> object:
    """Score one canonical tag record per independent observation root."""
    context = filetype_validation_context(engine, file_path)
    capability = filetype_mapping_get(context, 'execution_capability', 'unknown')
    evidence, root_records = _filetype_tag_evidence(tags)
    high = filetype_text_set(filetype_mapping_get(context, 'high_risk_buckets', set()))
    rare = filetype_text_set(filetype_mapping_get(context, 'rare_buckets', set()))
    normal = filetype_text_set(filetype_mapping_get(context, 'normal_buckets', set()))
    records = []
    score = 0.0
    for record in root_records:
        tag = record.canonical_tag_id
        bucket = tag_score_bucket(tag)
        evidence_name, evidence_confidence = evidence_level_for_tag(
            tag,
            strings_blob=strings_blob,
            path=file_path,
            api_calls=api_calls,
            ordered_events=ordered_events,
        )
        nonexec_violation = capability in NON_EXECUTION_CAPABILITIES and bucket in HIGH_RISK_BUCKETS
        if nonexec_violation:
            severity = max(0.2, evidence_confidence)
        elif bucket in high:
            severity = 0.75 * evidence_confidence
        elif bucket in rare:
            severity = 0.35 * evidence_confidence
        elif bucket in normal:
            severity = 0.0
        else:
            severity = 0.12 * evidence_confidence
        score += severity
        records.append({
            'tag': tag,
            'bucket': bucket,
            'evidence': evidence_name,
            'confidence': evidence_confidence,
            'nonexec_execution_violation': bool(nonexec_violation),
            'filetype_policy': (
                'high_risk' if bucket in high else 'rare' if bucket in rare
                else 'normal' if bucket in normal else 'unknown'
            ),
            'evidence_id': record.evidence_id,
            'root_observation_id': record.root_observation_id,
            'evidence_kind': record.evidence_kind,
        })
    for record in evidence.records:
        if record.evidence_kind != 'failure':
            continue
        records.append({
            'tag': record.canonical_tag_id,
            'bucket': 'other_behavior',
            'evidence': 'unavailable',
            'confidence': 0.0,
            'nonexec_execution_violation': False,
            'filetype_policy': 'unavailable',
            'evidence_id': record.evidence_id,
            'root_observation_id': record.root_observation_id,
            'evidence_kind': 'failure',
            'unavailable_reason': record.unavailable_reason,
        })
    return {
        'context': context,
        'filetype_anomaly': filetype_anomaly_probability(score, len(root_records)),
        'nonexec_execution_violation': any(row['nonexec_execution_violation'] for row in records),
        'records': records[:80],
        'tag_evidence_summary': dict(evidence.summary),
        'tag_evidence_kinds_consumed': tuple(sorted(_FILETYPE_EVIDENCE_KINDS)),
    }


__all__ = ('filetype_bucket_model_signal',)
