"""Canonical tag-evidence finalization and publication projection."""
from __future__ import annotations

import hashlib

from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
    detection_observations,
)
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.contracts.tag_evidence import (
    TagEvidenceRecord,
    active_tag_evidence_records,
    deterministic_tag_evidence_id,
    tag_evidence_observation_fields,
    tag_evidence_records,
)
from Virus_Scan.contracts.tag_vocabulary import TAG_VOCABULARY_VERSION
from Virus_Scan.detection.chains.composite.behavior_intent import behavior_intent_filter_tags
from Virus_Scan.detection.contracts.tag_validation import validate_tags_for_path
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.profiles.profile_policy import apply_profile_updater_baseline, suppress_profile_bytecode_noise
from Virus_Scan.detection.registries.tag_behavior.vocabulary_graph import TAG_DERIVATION_GRAPH_VERSION
from Virus_Scan.detection.tags.heuristics.behavior_derivation import derive_behavior_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    canonical_tag_name,
    normalize_tag_evidence,
)
from Virus_Scan.detection.tags.heuristics.runtime_library_policy import (
    apply_detection_library_behavior_baseline,
    apply_engine_runtime_capability_tags,
    enforce_runtime_library_post_derive_gate,
    suppress_runtime_binary_capability_noise,
)
from Virus_Scan.detection.tags.process.spyware_gate import gate_spyware_collection_chains
from Virus_Scan.utils.reference_url_policy import suppress_reference_url_false_positives

TAG_FINALIZATION_VERSION = "stage2636_10011_tag_evidence_finalization_v2"


def _source_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_tag_finalization_source",
        unsupported_reason="tag_finalization_source_rejected",
    )
    return "tag_finalization" if reason or not str.strip(text) else str.strip(text)


def _exact_text(value: object) -> str:
    return str.__str__(value) if type(value) is str else ""


def _artifact_context(
    *, path: object, strings_blob: object,
) -> tuple[str, ObservationSourceLocation]:
    path_text = _exact_text(path).strip()
    blob_text = _exact_text(strings_blob)
    if blob_text:
        digest = hashlib.sha256(blob_text.encode("utf-8", "surrogatepass")).hexdigest()
        artifact = "content_sha256:" + digest
        return artifact, ObservationSourceLocation(
            "file_content", locator=path_text or artifact,
        )
    if path_text:
        artifact = "path:" + path_text
        return artifact, ObservationSourceLocation("file_path", locator=path_text)
    return "", ObservationSourceLocation("unavailable")



def _validated_tag_set(values: object) -> frozenset[str]:
    if type(values) not in (tuple, list):
        return frozenset()
    return frozenset(
        canonical for value in values
        for canonical in (canonical_tag_name(value),)
        if canonical
    )


def _filter_observations(
    observations: tuple[DetectionObservation, ...],
    allowed: frozenset[str],
) -> tuple[DetectionObservation, ...]:
    return tuple(
        observation for observation in observations
        if canonical_tag_name(observation.tag) in allowed
    )


def _filter_evidence(
    bundle: TagEvidence,
    allowed: frozenset[str],
) -> TagEvidence:
    records = tuple(
        record for record in bundle.records
        if record.evidence_kind == "failure"
        or record.polarity == "negative"
        or canonical_tag_name(record.canonical_tag_id) in allowed
        or canonical_tag_name(record.publication_name) in allowed
    )
    return TagEvidence.from_records(records, reasons=dict(bundle.reasons))


def _raw_observations(
    tags: object,
    *,
    source: str,
    path: object,
    strings_blob: object,
) -> tuple[DetectionObservation, ...]:
    if type(tags) not in (tuple, list):
        return ()
    values = tuple(value for value in tags if type(value) is str and value)
    if not values:
        return ()
    del path, strings_blob
    return tuple(
        DetectionObservation.create(
            tag=value,
            producer_id=source,
            stage_id="legacy_flat_tag_projection",
            modality="unavailable",
            source_location=ObservationSourceLocation("unavailable"),
            timing_provenance="unavailable",
            integrity_status="unavailable",
            directness="unavailable",
            confidence=0.0,
            unavailable_reason="detection_observation_unstructured_input",
        )
        for value in values
    )


def _canonical_input_bundle(
    tags: object,
    *,
    path: object,
    strings_blob: object,
    source: str,
) -> tuple[TagEvidence, tuple[str, ...]]:
    if type(tags) in (tuple, list) and tags and all(type(item) is TagEvidence for item in tags):
        merged = TagEvidence.from_records(tuple(
            record for bundle in tags for record in bundle.records
        ))
        input_tags = tuple(merged.tags)
        validated = tuple(validate_tags_for_path(
            input_tags, path=path, strings_blob=strings_blob, source=source,
        ))
        return _filter_evidence(merged, _validated_tag_set(validated)), validated
    if type(tags) is TagEvidence:
        input_tags = tuple(tags.tags)
        validated = tuple(validate_tags_for_path(
            input_tags, path=path, strings_blob=strings_blob, source=source,
        ))
        return _filter_evidence(tags, _validated_tag_set(validated)), validated

    observations = detection_observations(tags)
    if observations:
        validated = tuple(validate_tags_for_path(
            tuple(observation.tag for observation in observations),
            path=path,
            strings_blob=strings_blob,
            source=source,
        ))
        filtered = _filter_observations(observations, _validated_tag_set(validated))
        return normalize_tag_evidence(
            filtered,
            source_detector=source,
            source_stage="validated_observation",
            derive=True,
        ), validated

    raw_values = tuple(tags) if type(tags) in (tuple, list) else (() if tags is None else (tags,))
    validated = tuple(validate_tags_for_path(
        raw_values, path=path, strings_blob=strings_blob, source=source,
    ))
    observations = _raw_observations(
        validated, source=source, path=path, strings_blob=strings_blob,
    )
    if observations:
        return normalize_tag_evidence(
            observations,
            source_detector=source,
            source_stage="validated_observation",
            derive=True,
        ), validated
    return normalize_tag_evidence(
        validated,
        source_detector=source,
        source_stage="validated_observation",
        derive=True,
    ), validated


def _apply_string_policies(
    tags: object, *, path: object, strings_blob: object, source: str,
) -> list[str]:
    url_clean = suppress_reference_url_false_positives(tags, path=path, strings_blob=strings_blob)
    updater_clean = apply_profile_updater_baseline(url_clean, path=path, strings_blob=strings_blob)
    renpy_clean = suppress_profile_bytecode_noise(updater_clean, path=path, strings_blob=strings_blob)
    runtime_clean = suppress_runtime_binary_capability_noise(renpy_clean, path=path, strings_blob=strings_blob)
    baseline_clean = apply_detection_library_behavior_baseline(runtime_clean, path=path, strings_blob=strings_blob)
    behavior_clean = behavior_intent_filter_tags(
        baseline_clean, path=path, strings_blob=strings_blob, source=source,
    )
    updater_gated = apply_profile_updater_baseline(behavior_clean, path=path, strings_blob=strings_blob)
    chain_gated = gate_spyware_collection_chains(updater_gated, path=path, strings_blob=strings_blob)
    post_runtime = enforce_runtime_library_post_derive_gate(chain_gated, path=path, strings_blob=strings_blob)
    baseline_final = apply_detection_library_behavior_baseline(post_runtime, path=path, strings_blob=strings_blob)
    engine_runtime_final = apply_engine_runtime_capability_tags(
        baseline_final, path=path, strings_blob=strings_blob,
    )
    url_final = suppress_reference_url_false_positives(
        engine_runtime_final, path=path, strings_blob=strings_blob,
    )
    return list(gate_spyware_collection_chains(url_final, path=path, strings_blob=strings_blob))


def _suppression_record(parent: TagEvidenceRecord, *, source: str) -> TagEvidenceRecord:
    rule_id = TAG_FINALIZATION_VERSION + ":suppression"
    return TagEvidenceRecord(
        canonical_tag_id=parent.canonical_tag_id,
        publication_name=parent.publication_name,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=parent.root_observation_id,
            canonical_tag_id=parent.canonical_tag_id,
            evidence_kind="suppression",
            source_detector=source + ":policy",
            source_stage="finalization",
            parent_evidence_ids=(parent.evidence_id,),
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=rule_id,
        ),
        source_detector=source + ":policy",
        source_stage="finalization",
        evidence_kind="suppression",
        parent_evidence_ids=(parent.evidence_id,),
        confidence=1.0,
        support=1.0,
        polarity="negative",
        behavior_bucket=parent.behavior_bucket,
        attack_phase=parent.attack_phase,
        scoreability_class="suppressed",
        correlation_group=parent.correlation_group,
        root_observation_id=parent.root_observation_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=rule_id,
        unavailable_reason="tag_removed_by_finalization_policy",
        **tag_evidence_observation_fields(parent, directness="context"),
    )


def _policy_context_observation(
    tag: str,
    *,
    source: str,
    path: object,
    strings_blob: object,
) -> DetectionObservation:
    artifact, location = _artifact_context(path=path, strings_blob=strings_blob)
    return DetectionObservation.create(
        tag=tag,
        producer_id=source + ":policy",
        stage_id="finalization",
        modality="metadata" if artifact else "unavailable",
        artifact_identity=artifact,
        source_location=location,
        timing_provenance="not_observed",
        integrity_status="unverified" if artifact else "unavailable",
        directness="context" if artifact else "unavailable",
        confidence=1.0 if artifact else 0.0,
        unavailable_reason="" if artifact else "tag_policy_context_identity_unavailable",
    )


def _policy_addition_record(
    tag: str,
    parents: tuple[TagEvidenceRecord, ...],
    *,
    source: str,
    path: object,
    strings_blob: object,
) -> TagEvidenceRecord:
    parent_ids = tuple(dict.fromkeys(record.evidence_id for record in parents))[:32]
    if parents:
        primary = parents[0]
        root_id = primary.root_observation_id
        evidence_kind = "derived"
        behavior_bucket = primary.behavior_bucket
        attack_phase = primary.attack_phase
        correlation_group = primary.correlation_group
        confidence = min(record.confidence for record in parents)
        support = min(record.support for record in parents)
        observation_fields = tag_evidence_observation_fields(primary, directness="derived")
        unavailable_reason = primary.unavailable_reason
    else:
        observation = _policy_context_observation(
            tag, source=source, path=path, strings_blob=strings_blob,
        )
        root_id = observation.root_observation_id
        evidence_kind = "observed" if not observation.unavailable_reason else "failure"
        behavior_bucket = "other_behavior"
        attack_phase = "unknown"
        correlation_group = ""
        confidence = observation.confidence
        support = 1.0 if not observation.unavailable_reason else 0.0
        observation_fields = {
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
            "directness": observation.directness,
        }
        unavailable_reason = observation.unavailable_reason
    rule_id = TAG_FINALIZATION_VERSION + ":addition:" + tag
    return TagEvidenceRecord(
        canonical_tag_id=tag,
        publication_name=tag,
        evidence_id=deterministic_tag_evidence_id(
            root_observation_id=root_id,
            canonical_tag_id=tag,
            evidence_kind=evidence_kind,
            source_detector=source + ":policy",
            source_stage="finalization",
            parent_evidence_ids=parent_ids,
            vocabulary_version=TAG_VOCABULARY_VERSION,
            rule_version=rule_id,
        ),
        source_detector=source + ":policy",
        source_stage="finalization",
        evidence_kind=evidence_kind,
        parent_evidence_ids=parent_ids,
        confidence=confidence,
        support=support,
        polarity="positive" if evidence_kind != "failure" else "unavailable",
        behavior_bucket=behavior_bucket,
        attack_phase=attack_phase,
        scoreability_class="support" if evidence_kind != "failure" else "none",
        correlation_group=correlation_group,
        root_observation_id=root_id,
        vocabulary_version=TAG_VOCABULARY_VERSION,
        rule_version=rule_id,
        unavailable_reason=unavailable_reason,
        raw_observation_name=tag if evidence_kind == "observed" else "",
        **observation_fields,
    )



def validate_tag_evidence_input_for_path(
    tags: object,
    path: object = None,
    strings_blob: object = "",
    source: object = "",
) -> TagEvidence:
    """Validate and normalize one scanner-stage input without finalizing it.

    This is the canonical append boundary for evidence generations. It preserves
    physical producer/root fields and rejects policy-invalid scanner terms, but
    deliberately leaves behavior derivation and final suppression to the single
    generation finalizer.
    """
    source_name = _source_text(source)
    normalized, validated = _canonical_input_bundle(
        tags, path=path, strings_blob=strings_blob, source=source_name,
    )
    return TagEvidence.from_records(normalized.records, reasons={
        "version": TAG_FINALIZATION_VERSION,
        "source": source_name,
        "validated_input_count": len(validated),
        "generation_input_only": True,
    })

def _finalize_tag_evidence_for_path(
    tags: object,
    path: object = None,
    strings_blob: object = "",
    source: object = "",
) -> TagEvidence:
    """Execute the one canonical validation/derivation/suppression pipeline."""
    source_name = _source_text(source)
    normalized, validated = _canonical_input_bundle(
        tags,
        path=path,
        strings_blob=strings_blob,
        source=source_name,
    )
    behavior_records = derive_behavior_evidence(normalized.records)
    behavior_bundle = TagEvidence.from_records(behavior_records)
    policy_tags = _apply_string_policies(
        behavior_bundle.tags,
        path=path,
        strings_blob=strings_blob,
        source=source_name,
    )
    final_set = frozenset(policy_tags)
    active_before = frozenset(behavior_bundle.tags)
    added = tuple(tag for tag in policy_tags if tag not in active_before)
    addition_parents = tuple(
        record for record in active_tag_evidence_records(behavior_records)
        if record.evidence_kind in {"observed", "normalized", "derived", "composite"}
        and record.polarity == "positive"
        and record.has_physical_identity
    )[:32]
    additions = tuple(
        _policy_addition_record(
            tag,
            addition_parents,
            source=source_name,
            path=path,
            strings_blob=strings_blob,
        )
        for tag in added
    )
    combined = tuple((*behavior_records, *additions))
    suppressions = tuple(
        _suppression_record(record, source=source_name)
        for record in tag_evidence_records(combined)
        if record.evidence_kind != "suppression"
        and record.publication_name not in final_set
        and record.canonical_tag_id not in final_set
    )
    reasons = {
        "version": TAG_FINALIZATION_VERSION,
        "source": source_name,
        "validated_input_count": len(validated),
        "canonical_input_count": len(normalized.tags),
        "policy_added_count": len(added),
        "policy_suppressed_count": len(suppressions),
        "derivation_graph_version": TAG_DERIVATION_GRAPH_VERSION,
    }
    return TagEvidence.from_records((*combined, *suppressions), reasons=reasons)


__all__ = (
    "TAG_FINALIZATION_VERSION",
    "validate_tag_evidence_input_for_path",
)
