"""Canonical detection tag evidence normalization and publication projection."""
from __future__ import annotations

from Virus_Scan.contracts.detection_observation import (
    DETECTION_OBSERVATION_UNAVAILABLE_TAG,
    DetectionObservation,
    ObservationSourceLocation,
    detection_observations,
)
from Virus_Scan.contracts.static_program_analysis import (
    static_observation_reference_from_detection,
)
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.contracts.tag_evidence import (
    TAG_EVIDENCE_SCHEMA_VERSION,
    TagEvidenceRecord,
    deterministic_tag_evidence_id,
    tag_evidence_observation_fields,
)
from Virus_Scan.contracts.tag_vocabulary import TAG_VOCABULARY_VERSION
from Virus_Scan.contracts.tag_taxonomy import (
    TAG_CLASS_ANALYTIC_CANDIDATE,
    TAG_CLASS_ATOMIC_OBSERVATION,
    TAG_CLASS_UNAVAILABLE,
    TAG_CONTEXT_ONLY_MODALITIES,
)
from Virus_Scan.detection.registries.tag_taxonomy_registry import tag_class_for
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.registries.tag_behavior.vocabulary_graph import (
    MAX_TAG_DERIVATION_DEPTH,
    MAX_TAG_DERIVATION_OUTPUTS,
    TAG_DERIVATION_GRAPH_VERSION,
    attack_phase_for_tag,
    derivation_rules_for,
)
from Virus_Scan.detection.tags.heuristics.vocabulary import (
    canonical_raw_tag_list as _vocab_canonical_raw_tag_list,
    canonical_raw_tag_name as _vocab_canonical_raw_tag_name,
    canonical_reporting_tag as _vocab_canonical_reporting_tag,
    canonical_tag_name as _vocab_canonical_tag_name,
    canonicalize_event_token as _vocab_canonicalize_event_token,
)
from Virus_Scan.utils.tagging import (
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    ordered_unique_tags,
)

TAG_NORMALIZATION_RECOVERABLE_EXCEPTIONS = (
    OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError,
)


def canonical_raw_tag_list(tags: object) -> object:
    return _vocab_canonical_raw_tag_list(ordered_unique_tags(tags))


def canonical_raw_tag_name(tag: object) -> object:
    return _vocab_canonical_raw_tag_name(tag)


def canonical_reporting_tag(tag: object) -> object:
    return _vocab_canonical_reporting_tag(tag)


def canonical_tag_name(tag: object) -> object:
    return _vocab_canonical_tag_name(tag)


def canonicalize_event_token(event: object) -> object:
    return _vocab_canonicalize_event_token(event)


def _normalization_text(value: object, *, default: str) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_tag_normalization_context",
        unsupported_reason="unsafe_tag_normalization_context_rejected",
    )
    if reason:
        return default
    return str.strip(text) or default


def _unstructured_tag_observation(
    value: object,
    *,
    producer_id: str,
    stage_id: str,
) -> DetectionObservation:
    """Project a raw legacy tag as explicitly unavailable, never as hydrated authority."""
    tag = (
        str.__str__(value).strip().lower()
        if type(value) is str and str.__str__(value).strip()
        else DETECTION_OBSERVATION_UNAVAILABLE_TAG
    )
    return DetectionObservation.create(
        tag=tag,
        producer_id=producer_id,
        stage_id=stage_id,
        modality="unavailable",
        source_location=ObservationSourceLocation("unavailable"),
        timing_provenance="unavailable",
        integrity_status="unavailable",
        directness="unavailable",
        confidence=0.0,
        unavailable_reason="detection_observation_unstructured_input",
    )


def _observation_fields(
    observation: DetectionObservation,
    *,
    directness: str | None = None,
) -> dict[str, object]:
    return {
        "observation_id": observation.observation_id,
        "modality": observation.modality,
        "platform": observation.platform,
        "actor_identity": observation.actor_identity,
        "target_identity": observation.target_identity,
        "artifact_identity": observation.artifact_identity,
        "process_identity": observation.process_identity,
        "host_identity": observation.host_identity,
        "connection_identity": observation.connection_identity,
        "source_location": observation.source_location,
        "ordinal": observation.ordinal,
        "timestamp": observation.timestamp,
        "timing_provenance": observation.timing_provenance,
        "integrity_status": observation.integrity_status,
        "directness": observation.directness if directness is None else directness,
    }


def _parent_observation_fields(
    parent: TagEvidenceRecord,
    *,
    directness: str | None = None,
) -> dict[str, object]:
    return tag_evidence_observation_fields(parent, directness=directness)

def _tag_behavior_bucket(tag: str) -> str:
    tag_to_behavior = detection_registry_value("TAG_TO_BEHAVIOR", {})
    items = no_hook_mapping_items(tag_to_behavior)
    if items is None:
        return "other_behavior"
    bucket = next((value for key, value in items if key == tag), "other_behavior")
    return bucket if type(bucket) is str and bucket else "other_behavior"


def _observed_scoreability(tag: str, bucket: str) -> tuple[str, str]:
    tag_class = tag_class_for(tag)
    if tag_class in {"", TAG_CLASS_ANALYTIC_CANDIDATE, TAG_CLASS_UNAVAILABLE}:
        return "none", ""
    if tag_class != TAG_CLASS_ATOMIC_OBSERVATION:
        return "support", ""
    concrete = frozenset(detection_registry_value("CONCRETE_SCORE_TAGS", ()))
    weak = frozenset(detection_registry_value("TAG_WEAK_CONTEXT_ONLY", ()))
    structural = frozenset(detection_registry_value("TAG_STRUCTURAL_ONLY", ()))
    if tag in weak or tag in structural:
        return "support", ""
    if tag in concrete:
        return "scoreable", bucket if bucket != "other_behavior" else tag
    return "support", ""


def _mapping_value(value: object, key: str) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    return next((item for name, item in items if name == key), None)


def _static_flow_identity(observation: DetectionObservation) -> str:
    if observation.modality not in {"static_control_flow", "static_structure"}:
        return ""
    try:
        reference = static_observation_reference_from_detection(observation)
    except (TypeError, ValueError):
        return ""
    return reference.flow_identity


def _observed_record(observation: DetectionObservation) -> TagEvidenceRecord:
    raw_name = canonical_raw_tag_name(observation.tag)
    canonical = canonical_tag_name(raw_name)
    root_id = observation.root_observation_id
    is_failure = bool(
        observation.unavailable_reason
        or canonical in {
            TAG_NORMALIZATION_FAILURE_EVIDENCE,
            "detection_stage_degraded",
        }
    )
    source_detector = observation.producer_id
    source_stage = observation.stage_id
    bucket = _tag_behavior_bucket(canonical)
    scoreability, group = _observed_scoreability(canonical, bucket)
    taxonomy_class = tag_class_for(canonical)
    context_only_modality = observation.modality in TAG_CONTEXT_ONLY_MODALITIES
    record_directness = observation.directness
    if not is_failure and (
        taxonomy_class != TAG_CLASS_ATOMIC_OBSERVATION or context_only_modality
    ):
        record_directness = "context"
    if not is_failure and context_only_modality:
        scoreability = "support"
        group = ""
    flow_identity = _static_flow_identity(observation)
    if taxonomy_class == TAG_CLASS_ATOMIC_OBSERVATION and flow_identity:
        group = flow_identity
    if raw_name != canonical and not is_failure:
        scoreability = "raw"
        group = ""
    if is_failure:
        scoreability = "none"
        group = ""
    kind = "failure" if is_failure else "observed"
    polarity = "unavailable" if is_failure else "positive"
    unavailable_reason = observation.unavailable_reason or (
        "tag_normalization_input_rejected" if is_failure else ""
    )
    return TagEvidenceRecord(
        canonical_tag_id=canonical or TAG_NORMALIZATION_FAILURE_EVIDENCE,
        publication_name=canonical or TAG_NORMALIZATION_FAILURE_EVIDENCE,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=root_id,
            canonical_tag_id=canonical or TAG_NORMALIZATION_FAILURE_EVIDENCE,
            evidence_kind=kind,
            source_detector=source_detector,
            source_stage=source_stage,
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=TAG_DERIVATION_GRAPH_VERSION,
        ),
        source_detector=source_detector,
        source_stage=source_stage,
        evidence_kind=kind,
        confidence=0.0 if is_failure else observation.confidence,
        support=0.0 if is_failure else 1.0,
        polarity=polarity,
        behavior_bucket=bucket,
        attack_phase=attack_phase_for_tag(canonical),
        scoreability_class=scoreability,
        correlation_group=group,
        root_observation_id=root_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=TAG_DERIVATION_GRAPH_VERSION,
        unavailable_reason=unavailable_reason,
        raw_observation_name=raw_name,
        **_observation_fields(observation, directness=record_directness),
    )


def _integrity_preference(value: str) -> int:
    if value == "verified":
        return 0
    if value == "partial":
        return 1
    if value == "unverified":
        return 2
    if value == "unavailable":
        return 3
    return 9


def _directness_preference(value: str) -> int:
    if value == "direct":
        return 0
    if value == "derived":
        return 1
    if value == "context":
        return 2
    if value == "unavailable":
        return 3
    return 9


def _observed_record_preference(record: TagEvidenceRecord) -> tuple[object, ...]:
    """Rank duplicate physical projections without depending on arrival order."""
    return (
        bool(record.unavailable_reason),
        _integrity_preference(record.integrity_status),
        _directness_preference(record.directness),
        -record.confidence,
        -record.support,
        record.modality,
        record.source_detector,
        record.source_stage,
        record.observation_id,
        record.evidence_id,
    )


def _normalized_record(parent: TagEvidenceRecord) -> TagEvidenceRecord:
    bucket = _tag_behavior_bucket(parent.canonical_tag_id)
    scoreability, group = _observed_scoreability(parent.canonical_tag_id, bucket)
    rule_id = TAG_VOCABULARY_VERSION + ":synonym"
    return TagEvidenceRecord(
        canonical_tag_id=parent.canonical_tag_id,
        publication_name=parent.canonical_tag_id,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=parent.root_observation_id,
            canonical_tag_id=parent.canonical_tag_id,
            evidence_kind="normalized",
            source_detector=parent.source_detector,
            source_stage=parent.source_stage,
            parent_evidence_ids=(parent.evidence_id,),
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=rule_id,
        ),
        source_detector=parent.source_detector,
        source_stage=parent.source_stage,
        evidence_kind="normalized",
        parent_evidence_ids=(parent.evidence_id,),
        confidence=parent.confidence,
        support=parent.support,
        polarity=parent.polarity,
        behavior_bucket=bucket,
        attack_phase=attack_phase_for_tag(parent.canonical_tag_id),
        scoreability_class=scoreability,
        correlation_group=group,
        root_observation_id=parent.root_observation_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=rule_id,
        raw_observation_name=parent.raw_observation_name,
        **_parent_observation_fields(parent),
    )

def _archive_inner_record(parent: TagEvidenceRecord) -> TagEvidenceRecord | None:
    prefix = "archive_inner:"
    if not parent.canonical_tag_id.startswith(prefix):
        return None
    target = canonical_tag_name(parent.canonical_tag_id[len(prefix):])
    if not target:
        return None
    bucket = _tag_behavior_bucket(target)
    scoreability, group = _observed_scoreability(target, bucket)
    rule_id = TAG_DERIVATION_GRAPH_VERSION + ":archive_inner_projection"
    return TagEvidenceRecord(
        canonical_tag_id=target,
        publication_name=target,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=parent.root_observation_id,
            canonical_tag_id=target,
            evidence_kind="derived",
            source_detector=parent.source_detector,
            source_stage=parent.source_stage,
            parent_evidence_ids=(parent.evidence_id,),
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=rule_id,
        ),
        source_detector=parent.source_detector,
        source_stage=parent.source_stage,
        evidence_kind="derived",
        parent_evidence_ids=(parent.evidence_id,),
        confidence=parent.confidence,
        support=parent.support,
        polarity=parent.polarity,
        behavior_bucket=bucket,
        attack_phase=attack_phase_for_tag(target),
        scoreability_class=scoreability,
        correlation_group=group,
        root_observation_id=parent.root_observation_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=rule_id,
        raw_observation_name=parent.raw_observation_name,
        **_parent_observation_fields(parent, directness="derived"),
    )


def _derived_record(parent: TagEvidenceRecord, target_tag: str, rule_id: str) -> TagEvidenceRecord:
    bucket = _tag_behavior_bucket(target_tag)
    return TagEvidenceRecord(
        canonical_tag_id=target_tag,
        publication_name=target_tag,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=parent.root_observation_id,
            canonical_tag_id=target_tag,
            evidence_kind="derived",
            source_detector=parent.source_detector,
            source_stage=parent.source_stage,
            parent_evidence_ids=(parent.evidence_id,),
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=rule_id,
        ),
        source_detector=parent.source_detector,
        source_stage=parent.source_stage,
        evidence_kind="derived",
        parent_evidence_ids=(parent.evidence_id,),
        confidence=max(0.0, min(1.0, parent.confidence * 0.9)),
        support=parent.support,
        polarity=parent.polarity if parent.polarity != "unavailable" else "unavailable",
        behavior_bucket=bucket,
        attack_phase=attack_phase_for_tag(target_tag),
        scoreability_class="support",
        correlation_group=parent.correlation_group,
        root_observation_id=parent.root_observation_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=rule_id,
        unavailable_reason=parent.unavailable_reason,
        **_parent_observation_fields(parent, directness="derived"),
    )


def _bounded_derivation(records: tuple[TagEvidenceRecord, ...]) -> tuple[TagEvidenceRecord, ...]:
    out = list(records)
    seen = {(record.root_observation_id, record.canonical_tag_id, record.evidence_kind) for record in records}
    frontier = list(records)
    depth = 0
    while frontier and depth < MAX_TAG_DERIVATION_DEPTH and len(out) < MAX_TAG_DERIVATION_OUTPUTS:
        next_frontier: list[TagEvidenceRecord] = []
        for parent in frontier:
            if parent.evidence_kind in {"failure", "suppression"}:
                continue
            for rule in derivation_rules_for(parent.canonical_tag_id):
                key = (parent.root_observation_id, rule.target_tag, rule.evidence_kind)
                if key in seen:
                    continue
                derived = _derived_record(parent, rule.target_tag, rule.rule_id)
                seen.add(key)
                out.append(derived)
                next_frontier.append(derived)
                if len(out) >= MAX_TAG_DERIVATION_OUTPUTS:
                    break
            if len(out) >= MAX_TAG_DERIVATION_OUTPUTS:
                break
        frontier = next_frontier
        depth += 1
    return tuple(out)


def normalize_tag_evidence(
    tags: object,
    *,
    source_detector: object = "tag_normalization",
    source_stage: object = "normalization",
    derive: bool = True,
) -> TagEvidence:
    """Build the canonical immutable evidence bundle from raw detector tags."""
    if type(tags) is TagEvidence:
        return tags
    detector = _normalization_text(source_detector, default="tag_normalization")
    stage = _normalization_text(source_stage, default="normalization")
    observations = detection_observations(tags)
    if not observations:
        raw_values = tuple(tags) if type(tags) in (tuple, list) else (tags,)
        observations = tuple(
            _unstructured_tag_observation(
                value,
                producer_id=detector,
                stage_id=stage,
            )
            for value in raw_values[:256]
            if value is not None
        )
    observed_by_key: dict[tuple[str, str], TagEvidenceRecord] = {}
    for observation in observations:
        record = _observed_record(observation)
        key = (record.root_observation_id, record.canonical_tag_id)
        previous = observed_by_key.get(key)
        if previous is None or _observed_record_preference(record) < _observed_record_preference(previous):
            observed_by_key[key] = record
    observed = tuple(observed_by_key.values())
    normalized = tuple(
        _normalized_record(record)
        for record in observed
        if (
            record.evidence_kind == "observed"
            and record.raw_observation_name != record.canonical_tag_id
        )
    )
    archive_inner = tuple(
        record for record in (_archive_inner_record(parent) for parent in observed)
        if record is not None
    )
    canonical_records = tuple((*observed, *normalized, *archive_inner))
    records = _bounded_derivation(canonical_records) if derive else canonical_records
    reasons = {
        "schema_version": TAG_EVIDENCE_SCHEMA_VERSION,
        "vocabulary_version": TAG_VOCABULARY_VERSION,
        "derivation_graph_version": TAG_DERIVATION_GRAPH_VERSION,
        "input_count": len(observations),
        "derivation_bounded": len(records) >= MAX_TAG_DERIVATION_OUTPUTS,
    }
    return TagEvidence.from_records(records, reasons=reasons)


def normalize_tags(tags: object) -> list[str]:
    """Return only the deterministic publication projection of canonical evidence."""
    return list(normalize_tag_evidence(tags).tags)


def normalize_timeline_event_name(event: object) -> object:
    """Return a stable reporting event name without creating evidence identity."""
    if type(event) is dict:
        event = next((
            value for key in ("tag", "behavior", "raw", "event")
            for value in (dict.get(event, key),)
            if type(value) is str and str.__str__(value).strip()
        ), "")
    if type(event) is str:
        return canonical_tag_name(event)
    if type(event) is DetectionObservation:
        return canonical_tag_name(event.tag)
    return ""


__all__ = (
    "TAG_NORMALIZATION_RECOVERABLE_EXCEPTIONS",
    "canonical_raw_tag_list",
    "canonical_raw_tag_name",
    "canonical_reporting_tag",
    "canonical_tag_name",
    "canonicalize_event_token",
    "normalize_tag_evidence",
    "normalize_tags",
    "normalize_timeline_event_name",
)
