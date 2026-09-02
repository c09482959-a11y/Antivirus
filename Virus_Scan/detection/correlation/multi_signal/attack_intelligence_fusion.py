"""Classifier record construction and independent-evidence fusion."""
from __future__ import annotations

from Virus_Scan.contracts.yara_hits import YaraHit
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_contracts import (
    AttackClassifierRecord, AttackClassifierSpec,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_policy import (
    ATTACK_ENSEMBLE_POLICY,
)
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence_inputs import (
    AttackIntelligenceYaraFamilyAlignment,
    classifier_root_profile,
    yara_for_family,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.classifier_evidence import (
    ClassifierEvidenceResult,
    merge_non_overlapping_classifier_contributions,
)


def unavailable_classifier_record(
    spec: AttackClassifierSpec,
    reason: str,
) -> AttackClassifierRecord:
    return AttackClassifierRecord(
        classifier_id=spec.classifier_id,
        classifier_version=spec.version,
        family=spec.family,
        matched_root_evidence_ids=(),
        matched_canonical_tag_ids=(),
        matched_yara_rule_ids=(),
        direct_evidence_count=0,
        inferred_evidence_count=0,
        correlation_groups=(),
        raw_score=0.0,
        family_probability=0.0,
        uncertainty=1.0,
        support=0,
        ready=False,
        rejected_reasons=(reason,),
        explanation_fields=(),
        yara_state="unavailable",
        production_threshold=spec.production_threshold,
    )


def _accepted_classifier_contributions(
    result: ClassifierEvidenceResult, accepted_roots: frozenset[str],
) -> tuple[object, ...]:
    return tuple(
        contribution for contribution in result.contributions
        if (
            contribution.root_observation_ids
            and frozenset(contribution.root_observation_ids) <= accepted_roots
        )
    )


def _classifier_probability(
    spec: AttackClassifierSpec,
    accepted_contributions: tuple[object, ...],
    reasons: list[str],
    matched_yara: tuple[str, ...],
) -> tuple[float, float]:
    accepted_score = sum(
        contribution.points for contribution in accepted_contributions
    )
    raw_score = round(min(spec.score_ceiling, max(0.0, accepted_score)), 6)
    probability = spec.calibrate(raw_score) if not reasons else 0.0
    if probability > 0.0 and matched_yara:
        probability = round(min(
            1.0, probability + ATTACK_ENSEMBLE_POLICY.yara_corroboration_bonus,
        ), 6)
    return raw_score, probability


def classifier_record(
    spec: AttackClassifierSpec,
    result: ClassifierEvidenceResult,
    tag_evidence: TagEvidence,
    yara_records: tuple[YaraHit, ...],
    *,
    yara_family_alignments: tuple[AttackIntelligenceYaraFamilyAlignment, ...],
) -> AttackClassifierRecord:
    result = merge_non_overlapping_classifier_contributions((result,))
    attributed_roots = tuple(sorted({
        root
        for contribution in result.contributions
        for root in contribution.root_observation_ids
    }))
    profile = classifier_root_profile(
        tag_evidence, attributed_roots, spec.required_evidence_kinds,
    )
    tag_roots = profile["root_ids"]
    direct_count = int(profile["direct_root_count"])
    inferred_count = int(profile["inferred_root_count"])
    reasons: list[str] = []
    if attributed_roots != tag_roots:
        reasons.append("classifier_root_attribution_invalid")
    if tag_roots and len(tag_roots) < spec.minimum_distinct_roots:
        reasons.append("insufficient_distinct_roots")
    if tag_roots and direct_count < spec.minimum_direct_roots:
        reasons.append("direct_observation_required")
    accepted = _accepted_classifier_contributions(
        result, frozenset(tag_roots),
    )
    matched_yara, yara_roots, yara_state = yara_for_family(
        yara_records, spec.family, alignments=yara_family_alignments,
    )
    raw_score, probability = _classifier_probability(
        spec, accepted, reasons, matched_yara,
    )
    roots = tuple(sorted({*tag_roots, *yara_roots}))
    direct_count += len(set(yara_roots) - set(tag_roots))
    support = len(roots)
    uncertainty = (
        1.0 if reasons or support == 0
        else round(max(0.05, 1.0 / (support + 1.0)), 6)
    )
    return AttackClassifierRecord(
        classifier_id=spec.classifier_id, classifier_version=spec.version,
        family=spec.family, matched_root_evidence_ids=roots,
        matched_canonical_tag_ids=profile["canonical_tags"],
        matched_yara_rule_ids=matched_yara, direct_evidence_count=direct_count,
        inferred_evidence_count=inferred_count,
        correlation_groups=profile["correlation_groups"], raw_score=raw_score,
        family_probability=probability, uncertainty=uncertainty, support=support,
        ready=not reasons, rejected_reasons=tuple(reasons),
        explanation_fields=tuple(sorted({
            *(contribution.label for contribution in accepted if contribution.label),
            *result.informational_hits,
        }))[:32],
        yara_state=yara_state, production_threshold=spec.production_threshold,
    )


def _independence_keys(record: AttackClassifierRecord) -> frozenset[str]:
    return frozenset((
        *("root:" + value for value in record.matched_root_evidence_ids),
        *("group:" + value for value in record.correlation_groups),
    ))


def fuse_classifier_records(
    records: tuple[AttackClassifierRecord, ...],
) -> dict[str, object]:
    """Fuse only independent ready family records with bounded noisy-OR."""
    if (
        type(records) is not tuple
        or len(records) > ATTACK_ENSEMBLE_POLICY.maximum_records
        or any(type(record) is not AttackClassifierRecord for record in records)
    ):
        raise TypeError("attack_classifier_record_tuple_required")
    classifier_ids = tuple(record.classifier_id for record in records)
    families = tuple(record.family for record in records)
    if len(classifier_ids) != len(set(classifier_ids)):
        raise ValueError("attack_classifier_record_id_duplicate")
    if len(families) != len(set(families)):
        raise ValueError("attack_classifier_record_family_duplicate")
    ordered = tuple(sorted(records, key=lambda record: record.classifier_id))
    candidates = sorted(
        (
            record for record in ordered
            if record.ready and record.family_probability >= record.production_threshold
        ),
        key=lambda record: (-record.family_probability, record.classifier_id),
    )
    used: set[str] = set()
    selected: list[AttackClassifierRecord] = []
    rejected_correlated: list[str] = []
    for record in candidates:
        keys = _independence_keys(record)
        if keys and keys & used:
            rejected_correlated.append(record.classifier_id)
            continue
        selected.append(record)
        used.update(keys)
    complement = 1.0
    for record in selected:
        complement *= 1.0 - record.family_probability
    aggregate = round(max(0.0, min(1.0, 1.0 - complement)), 6)
    support = sum(record.support for record in selected)
    uncertainty = round(
        1.0 if not selected else max(0.05, sum(
            record.uncertainty * record.family_probability for record in selected
        ) / max(1e-9, sum(record.family_probability for record in selected))),
        6,
    )
    best = max(
        candidates,
        key=lambda record: (record.family_probability, record.family, record.classifier_id),
        default=None,
    )
    return {
        "aggregate_probability": aggregate,
        "aggregate_uncertainty": uncertainty,
        "aggregate_support": support,
        "best_family": best.family if best else None,
        "family_probabilities": {
            record.family: record.family_probability for record in ordered
        },
        "independent_classifier_ids": tuple(record.classifier_id for record in selected),
        "correlated_classifier_ids_rejected_from_aggregate": tuple(sorted(rejected_correlated)),
        "hits": tuple(sorted({
            hit for record in ordered for hit in record.explanation_fields if hit
        }))[:64],
    }


__all__ = (
    "classifier_record", "fuse_classifier_records", "unavailable_classifier_record",
)
