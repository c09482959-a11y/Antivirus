"""Canonical independent attack-intelligence classifier ensemble."""
from __future__ import annotations

from Virus_Scan.contracts.yara_hits import YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    ATTACK_INTELLIGENCE_EVIDENCE_VERSION,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_policy import (
    ATTACK_ENSEMBLE_POLICY, ATTACK_ENSEMBLE_POLICY_RECORD,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_fusion import (
    classifier_record,
    fuse_classifier_records,
    unavailable_classifier_record,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_inputs import (
    ATTACK_INTELLIGENCE_YARA_ALIGNMENTS,
    AttackIntelligenceYaraFamilyAlignment,
    attack_yara_evidence,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_registry import ATTACK_INTELLIGENCE_CLASSIFIERS
from Virus_Scan.detection.correlation.multi_signal.cluster_feature_tags import decode_feature_tags_for_cluster
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.tags.heuristics.classifier_evidence import ClassifierEvidenceResult
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE, ordered_unique_tags

ATTACK_INTELLIGENCE_RECOVERABLE = (
    OSError, ValueError, TypeError, RuntimeError, KeyError, AttributeError, UnicodeError,
)
_ATTACK_CONSUMED_EVIDENCE_KINDS = frozenset({
    "observed", "normalized", "derived", "composite",
})


def _failure(stage_name: str, reason: object, context: str) -> object:
    return recoverable_failure_evidence(
        stage_name=stage_name,
        error=reason,
        error_source="detection.correlation.multi_signal.attack_intelligence",
        affected_context=context,
    )



def _reason_text(value: object, *, rejected_reason: str) -> str:
    if value is None or value == "":
        return ""
    if type(value) is str:
        return value[:160]
    return rejected_reason

def _attack_tags(value: object) -> tuple[TagEvidence, str]:
    if type(value) is not TagEvidence:
        return TagEvidence(reasons={"unavailable_reason": "attack_tag_evidence_required"}), "attack_tag_evidence_required"
    bundle = scoreable_tag_evidence(value, allowed_evidence_kinds=_ATTACK_CONSUMED_EVIDENCE_KINDS)
    return bundle, _reason_text(
        bundle.reasons.get("unavailable_reason"),
        rejected_reason="attack_tag_evidence_reason_rejected",
    )


def _decoded_tags(value: object) -> tuple[TagEvidence, str]:
    raw = ordered_unique_tags(value)
    if TAG_NORMALIZATION_FAILURE_EVIDENCE in raw or DETECTION_STAGE_DEGRADED_TAG in raw:
        return TagEvidence(reasons={"unavailable_reason": "attack_decoded_tags_rejected"}), "attack_decoded_tags_rejected"
    normalized = normalize_tag_evidence(
        raw, source_detector="attack_intelligence_decoder", source_stage="decoded_strings",
    )
    bundle = scoreable_tag_evidence(normalized, allowed_evidence_kinds=_ATTACK_CONSUMED_EVIDENCE_KINDS)
    return bundle, _reason_text(
        bundle.reasons.get("unavailable_reason"),
        rejected_reason="attack_decoded_tag_reason_rejected",
    )


def _normalized_inputs(
    tags: object,
    strings_blob: object,
    failures: list[object],
) -> TagEvidence:
    bundle, reason = _attack_tags(tags)
    if reason:
        failures.append(_failure("attack_intelligence_tag_context", reason, "tags"))
    text, text_reason = no_hook_text(
        strings_blob,
        missing_reason="attack_intelligence_text_missing",
        unsupported_reason="attack_intelligence_text_rejected",
    )
    if text_reason not in ("", "attack_intelligence_text_missing"):
        failures.append(_failure("attack_intelligence_text_context", text_reason, "strings_blob"))
    if not text:
        return bundle
    try:
        decoded, decoded_reason = _decoded_tags(decode_feature_tags_for_cluster(text))
        if decoded_reason:
            failures.append(_failure("attack_intelligence_cluster_feature_decode", decoded_reason, "strings_blob"))
        merged = TagEvidence.from_records(
            (*bundle.records, *decoded.records),
            reasons={
                "input_evidence_summary": dict(bundle.summary),
                "decoded_evidence_summary": dict(decoded.summary),
            },
        )
        return scoreable_tag_evidence(merged, allowed_evidence_kinds=_ATTACK_CONSUMED_EVIDENCE_KINDS)
    except ATTACK_INTELLIGENCE_RECOVERABLE as error:
        failures.append(_failure("attack_intelligence_cluster_feature_decode", error, "strings_blob"))
        return bundle


def _classifier_records(
    tag_evidence: TagEvidence,
    yara_records: object,
    failures: list[object],
    *,
    yara_family_alignments: tuple[AttackIntelligenceYaraFamilyAlignment, ...],
) -> tuple[object, ...]:
    records: list[object] = []
    for spec in ATTACK_INTELLIGENCE_CLASSIFIERS:
        try:
            result = spec.detector(tag_evidence)
            if type(result) is not ClassifierEvidenceResult:
                raise TypeError("attack_intelligence_classifier_result_required")
            records.append(classifier_record(
                spec, result, tag_evidence, yara_records,
                yara_family_alignments=yara_family_alignments,
            ))
        except ATTACK_INTELLIGENCE_RECOVERABLE as error:
            failures.append(_failure("attack_intelligence_classifier:" + spec.classifier_id, error, spec.classifier_id))
            records.append(unavailable_classifier_record(spec, "classifier_execution_failed"))
    return tuple(records)


def compute_attack_intelligence(
    tags: object,
    yara_hits: object,
    strings_blob: object = "",
    *,
    yara_family_alignments: tuple[AttackIntelligenceYaraFamilyAlignment, ...] = (
        ATTACK_INTELLIGENCE_YARA_ALIGNMENTS
    ),
) -> dict[str, object]:
    """Return independent calibrated classifier evidence without chain/MITRE aliases."""
    failures: list[object] = []
    tag_evidence = _normalized_inputs(tags, strings_blob, failures)
    yara_records, yara_state = attack_yara_evidence(yara_hits)
    if yara_state == YARA_HIT_NORMALIZATION_FAILURE_EVIDENCE or yara_state == "yara_input_rejected":
        failures.append(_failure("attack_intelligence_yara_context", "attack_yara_hits_rejected", "yara_hits"))
    records = _classifier_records(
        tag_evidence, yara_records, failures,
        yara_family_alignments=yara_family_alignments,
    )
    aggregate = fuse_classifier_records(records)
    failure_payload = failure_evidence_payload(tuple(failures))
    ready_classifier_count = sum(record.ready for record in records)
    unavailable_classifier_count = len(records) - ready_classifier_count
    tag_unavailable_reason = _reason_text(
        tag_evidence.reasons.get("unavailable_reason"),
        rejected_reason="attack_tag_evidence_reason_rejected",
    )
    ready = not tag_unavailable_reason and ready_classifier_count > 0
    unavailable_reason = (
        tag_unavailable_reason
        if tag_unavailable_reason
        else "all_attack_classifiers_unavailable" if not ready_classifier_count else ""
    )
    hits = list(aggregate["hits"])
    if failure_payload["degraded"]:
        hits.append("attack_intelligence_failure_evidence_recorded")
    return {
        "evidence_version": ATTACK_INTELLIGENCE_EVIDENCE_VERSION,
        "policy_version": ATTACK_ENSEMBLE_POLICY.version,
        "calibration_version": ATTACK_ENSEMBLE_POLICY.calibration_version,
        "evaluation_provenance": ATTACK_ENSEMBLE_POLICY.evaluation_provenance,
        "aggregate_method": ATTACK_ENSEMBLE_POLICY.aggregate_method,
        "aggregate_probability": aggregate["aggregate_probability"],
        "aggregate_uncertainty": aggregate["aggregate_uncertainty"],
        "aggregate_support": aggregate["aggregate_support"],
        "best_family": aggregate["best_family"],
        "family_probabilities": aggregate["family_probabilities"],
        "classifier_records": tuple(record.to_record() for record in records)[:ATTACK_ENSEMBLE_POLICY.maximum_records],
        "independent_classifier_ids": aggregate["independent_classifier_ids"],
        "correlated_classifier_ids_rejected_from_aggregate": aggregate["correlated_classifier_ids_rejected_from_aggregate"],
        "hits": tuple(sorted(set(hits)))[:64],
        "yara_state": yara_state,
        "ready": ready,
        "unavailable_reason": unavailable_reason,
        "ready_classifier_count": ready_classifier_count,
        "unavailable_classifier_count": unavailable_classifier_count,
        "degraded": failure_payload["degraded"],
        "failure_evidence": failure_payload["failures"],
        "confidence_degraded": failure_payload["confidence_degraded"],
        "json_record_required": failure_payload["json_record_required"],
        "replay_record_required": True,
        "tag_evidence_summary": dict(tag_evidence.summary),
        "tag_evidence_kinds_consumed": tuple(sorted(_ATTACK_CONSUMED_EVIDENCE_KINDS)),
        "policy": dict(ATTACK_ENSEMBLE_POLICY_RECORD),
    }


__all__ = ("ATTACK_INTELLIGENCE_CLASSIFIERS", "compute_attack_intelligence")
