"""Canonical score ownership for contextual expected-behavior scoring."""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.contracts.tag_evidence import (
    TagEvidenceRecord,
    contextual_dangerous_anchor_hits,
    distinct_root_tag_evidence_records,
)
from Virus_Scan.contracts.tag_evidence_persistence import (
    persisted_tag_observation_count_status,
)
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.detection.evidence.failure_evidence import (
    failure_evidence_payload,
    recoverable_failure_evidence,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.profiles.baseline_snapshot import read_extension_baseline_snapshot
from Virus_Scan.detection.profiles.selection import (
    DETECTION_PROFILE_NAMES,
    canonical_profile_name,
)
from Virus_Scan.detection.scoring.weighting.policy_constants import (
    CONTEXTUAL_BASELINE_COMMON_TAG_PROB,
    CONTEXTUAL_BASELINE_MAX_REDUCTION,
    CONTEXTUAL_BASELINE_MIN_FILES,
    CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR,
    CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR,
    CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB,
    CONTEXTUAL_BASELINE_VERSION,
    CONTEXTUAL_DANGEROUS_ANCHOR_TAGS,
    CONTEXTUAL_WEAK_NOISE_BUCKETS,
    HIGH_RISK_BUCKETS,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.utils.stages import normalize_profile_extension
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
)


ContextualValue = object
ContextualMapping = dict[str, ContextualValue]
ContextualScoreSignal = tuple[float, ContextualMapping]
ContextualFloatStatus = tuple[float, str]
ContextualCountStatus = tuple[int, str]
ContextualLookupStatus = tuple[ContextualValue, str]

_CONTEXTUAL_EVIDENCE_KINDS = frozenset({
    "observed", "normalized", "derived", "composite",
})


def _contextual_text(value: ContextualValue, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="contextual_text_missing",
        unsupported_reason="contextual_text_rejected",
    )
    if reason:
        return default
    return text or default


def _contextual_float_status(
    value: ContextualValue,
    default: float = 0.0,
    reason: str = "contextual_numeric_rejected",
) -> ContextualFloatStatus:
    return no_hook_finite_float(
        value,
        default=default,
        reason=reason,
        non_finite_reason="contextual_numeric_non_finite",
        allow_exact_text=True,
    )


def _contextual_float(value: ContextualValue, default: float = 0.0) -> float:
    numeric, _reason = _contextual_float_status(value, default)
    return numeric


def _contextual_count_status(
    value: ContextualValue,
    default: int = 0,
    reason: str = "contextual_count_rejected",
) -> ContextualCountStatus:
    numeric, numeric_reason = _contextual_float_status(value, default + 0.0, reason)
    if numeric_reason:
        return 0, numeric_reason
    if numeric < 0.0:
        return 0, ""
    return int(numeric), ""


def _contextual_probability(value: ContextualValue) -> float:
    return safe_clamp(_contextual_float(value), 0.0, 1.0)


def _contextual_score(value: ContextualValue) -> float:
    return safe_clamp(_contextual_float(value), 0.0, 100.0)


def _mapping_get_status(
    mapping: ContextualValue,
    key: str,
    default: ContextualValue | None = None,
) -> ContextualLookupStatus:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default, "contextual_mapping_rejected"
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value, ""
    return default, ""


def _contextual_failure_signal(
    reason: str,
    *,
    engine: str,
    file_path: ContextualValue,
    files_seen: int = 0,
    tag_evidence: TagEvidence | None = None,
) -> ContextualMapping:
    failure = recoverable_failure_evidence(
        stage_name="contextual_expected_behavior_signal",
        error_source="contextual_expected_behavior_signal",
        error=reason,
        affected_context=_contextual_text(file_path, "<unreadable_path>"),
    )
    payload = failure_evidence_payload((failure,))
    return {
        "version": CONTEXTUAL_BASELINE_VERSION,
        "applied": False,
        "reason": reason,
        "engine": engine,
        "extension": normalize_profile_extension(file_path),
        "files_seen": files_seen,
        "anchors": [],
        "expected_tags": [],
        "records": [],
        "distinct_root_count": 0,
        "tag_evidence_summary": (
            {} if tag_evidence is None else dict(tag_evidence.summary)
        ),
        "tag_evidence_kinds_consumed": tuple(sorted(_CONTEXTUAL_EVIDENCE_KINDS)),
        "reduction": 0.0,
        "failure_evidence": payload["failures"],
        "scanner_degraded": payload["degraded"],
        "confidence_degraded": payload["confidence_degraded"],
    }


@dataclass(frozen=True, slots=True)
class ContextualExpectedScoreRequest:
    """Canonical immutable request for one contextual score reduction."""

    score: ContextualValue
    engine: ContextualValue
    file_path: ContextualValue
    tag_evidence: TagEvidence
    routing_evidence_context: object | None = None
    router_identity: object | None = None


def _canonical_contextual_evidence(tags: ContextualValue) -> TagEvidence:
    if type(tags) is TagEvidence:
        return tags
    return normalize_tag_evidence(
        tags,
        source_detector="contextual_expected",
        source_stage="score_input",
        derive=True,
    )


def _contextual_root_records(tag_evidence: TagEvidence) -> tuple[TagEvidenceRecord, ...]:
    return distinct_root_tag_evidence_records(
        tag_evidence.records,
        allowed_evidence_kinds=_CONTEXTUAL_EVIDENCE_KINDS,
    )


def _contextual_anchor_tags(records: tuple[TagEvidenceRecord, ...]) -> list[str]:
    publications = tuple(record.publication_name for record in records)
    hits = set(contextual_dangerous_anchor_hits(publications))
    for record in records:
        if (
            record.canonical_tag_id in CONTEXTUAL_DANGEROUS_ANCHOR_TAGS
            or record.publication_name in CONTEXTUAL_DANGEROUS_ANCHOR_TAGS
            or record.behavior_bucket in HIGH_RISK_BUCKETS
        ):
            hits.add(record.publication_name or record.canonical_tag_id)
    return sorted(tag for tag in hits if tag)


def _contextual_expected_degraded_signal(
    *,
    engine: str,
    file_path: ContextualValue,
    files: int,
    anchors: list[str],
    tag_evidence: TagEvidence,
) -> ContextualMapping:
    failure = recoverable_failure_evidence(
        stage_name="contextual_expected_behavior_signal",
        error_source="contextual_expected_behavior_signal",
        error="tag_normalization_failure_evidence",
        affected_context=_contextual_text(file_path, "<unreadable_path>"),
    )
    payload = failure_evidence_payload((failure,))
    return {
        "version": CONTEXTUAL_BASELINE_VERSION,
        "applied": False,
        "reason": "tag_normalization_failure_evidence",
        "engine": engine,
        "extension": normalize_profile_extension(file_path),
        "files_seen": files,
        "anchors": anchors,
        "expected_tags": [],
        "records": [],
        "distinct_root_count": 0,
        "tag_evidence_summary": dict(tag_evidence.summary),
        "tag_evidence_kinds_consumed": tuple(sorted(_CONTEXTUAL_EVIDENCE_KINDS)),
        "reduction": 0.0,
        "failure_evidence": payload["failures"],
        "scanner_degraded": payload["degraded"],
        "confidence_degraded": payload["confidence_degraded"],
    }


def _contextual_expected_reduction_signal(
    *,
    engine: str,
    file_path: ContextualValue,
    persisted_tag_evidence: ContextualValue,
    tag_evidence: TagEvidence,
    root_records: tuple[TagEvidenceRecord, ...],
    files: int,
    anchors: list[str],
) -> ContextualMapping:
    records: list[dict[str, ContextualValue]] = []
    expected: list[str] = []
    weak_expected: list[str] = []
    scoreable_expected: list[str] = []
    expected_probabilities: list[float] = []
    strong_common = 0
    unavailable_count = 0
    base = {
        "version": CONTEXTUAL_BASELINE_VERSION,
        "engine": engine,
        "extension": normalize_profile_extension(file_path),
        "files_seen": files,
        "anchors": anchors,
        "distinct_root_count": len(root_records),
        "tag_evidence_summary": dict(tag_evidence.summary),
        "tag_evidence_kinds_consumed": tuple(sorted(_CONTEXTUAL_EVIDENCE_KINDS)),
    }
    if files < CONTEXTUAL_BASELINE_MIN_FILES:
        return {
            **base,
            "applied": False,
            "reason": "insufficient_engine_extension_history",
            "expected_tags": [],
            "records": [],
            "reduction": 0.0,
        }

    for record in sorted(
        root_records,
        key=lambda item: (
            item.publication_name,
            item.root_observation_id,
            item.evidence_id,
        ),
    ):
        tag = record.publication_name or record.canonical_tag_id
        tag_count, count_reason = persisted_tag_observation_count_status(
            persisted_tag_evidence,
            tag,
        )
        if count_reason:
            unavailable_count += 1
            records.append({
                "tag": tag,
                "canonical_tag_id": record.canonical_tag_id,
                "evidence_id": record.evidence_id,
                "root_observation_id": record.root_observation_id,
                "correlation_group": record.correlation_group,
                "evidence_kind": record.evidence_kind,
                "probability": 0.0,
                "observation_count": 0,
                "expected_for_engine_extension": False,
                "unavailable_reason": count_reason,
            })
            continue
        probability = _contextual_probability(tag_count / max(1.0, files + 0.0))
        is_anchor = (
            tag in CONTEXTUAL_DANGEROUS_ANCHOR_TAGS
            or record.canonical_tag_id in CONTEXTUAL_DANGEROUS_ANCHOR_TAGS
            or record.behavior_bucket in HIGH_RISK_BUCKETS
        )
        is_common = probability >= CONTEXTUAL_BASELINE_COMMON_TAG_PROB
        is_weak = (
            record.confidence < 0.6
            or record.support < 0.6
            or record.behavior_bucket in CONTEXTUAL_WEAK_NOISE_BUCKETS
            or record.scoreability_class in {"raw", "support", "none"}
        )
        records.append({
            "tag": tag,
            "canonical_tag_id": record.canonical_tag_id,
            "evidence_id": record.evidence_id,
            "root_observation_id": record.root_observation_id,
            "correlation_group": record.correlation_group,
            "evidence_kind": record.evidence_kind,
            "scoreability_class": record.scoreability_class,
            "behavior_bucket": record.behavior_bucket,
            "probability": probability,
            "observation_count": tag_count,
            "confidence": record.confidence,
            "support": record.support,
            "anchor": bool(is_anchor),
            "expected_for_engine_extension": bool(is_common and not is_anchor),
            "unavailable_reason": record.unavailable_reason,
        })
        if is_common and not is_anchor:
            expected.append(tag)
            expected_probabilities.append(probability)
            if probability >= CONTEXTUAL_BASELINE_STRONG_COMMON_TAG_PROB:
                strong_common += 1
            if is_weak:
                weak_expected.append(tag)
            else:
                scoreable_expected.append(tag)

    if not expected:
        result: ContextualMapping = {
            **base,
            "applied": False,
            "reason": "no_common_non_anchor_tags",
            "expected_tags": [],
            "records": records[:80],
            "reduction": 0.0,
        }
        if unavailable_count:
            result["scanner_degraded"] = True
            result["confidence_degraded"] = True
            result["unavailable_record_count"] = unavailable_count
        return result

    denominator = max(1, len(root_records))
    expected_ratio = len(expected) / denominator
    weak_ratio = len(weak_expected) / denominator
    avg_expected_prob = sum(expected_probabilities) / max(1, len(expected_probabilities))
    reduction = (
        expected_ratio * 10.0
        + weak_ratio * 8.0
        + avg_expected_prob * 5.0
        + min(6.0, strong_common * 1.5)
    )
    if anchors:
        reduction *= 0.35
    reduction = min(CONTEXTUAL_BASELINE_MAX_REDUCTION, max(0.0, reduction))
    result = {
        **base,
        "applied": reduction > 0.0,
        "reason": "learned_expected_engine_extension_tags",
        "expected_tags": sorted(set(expected)),
        "weak_expected_tags": sorted(set(weak_expected)),
        "scoreable_expected_tags": sorted(set(scoreable_expected)),
        "expected_root_count": len(expected),
        "expected_ratio": _contextual_probability(expected_ratio),
        "weak_expected_ratio": _contextual_probability(weak_ratio),
        "avg_expected_probability": _contextual_probability(avg_expected_prob),
        "records": records[:80],
        "reduction": reduction,
    }
    if unavailable_count:
        result["scanner_degraded"] = True
        result["confidence_degraded"] = True
        result["unavailable_record_count"] = unavailable_count
    return result


def _contextual_signal_from_evidence(
    *,
    engine: ContextualValue,
    file_path: ContextualValue,
    tag_evidence: TagEvidence,
    routing_evidence_context: object | None,
    router_identity: object | None,
) -> ContextualMapping:
    stable_engine = canonical_profile_name(engine)
    if stable_engine not in DETECTION_PROFILE_NAMES:
        stable_engine = "other"
    if routing_evidence_context is None:
        baseline = (
            read_extension_baseline_snapshot(stable_engine, file_path)
            if router_identity is None
            else read_extension_baseline_snapshot(
                stable_engine,
                file_path,
                router_identity=router_identity,
            )
        )
    else:
        baseline = (
            read_extension_baseline_snapshot(
                stable_engine,
                file_path,
                evidence_context=routing_evidence_context,
            )
            if router_identity is None
            else read_extension_baseline_snapshot(
                stable_engine,
                file_path,
                evidence_context=routing_evidence_context,
                router_identity=router_identity,
            )
        )
    files_value, files_value_reason = _mapping_get_status(baseline, "files", 0)
    if files_value_reason:
        return _contextual_failure_signal(
            files_value_reason,
            engine=stable_engine,
            file_path=file_path,
            tag_evidence=tag_evidence,
        )
    files, files_reason = _contextual_count_status(
        files_value,
        reason="unsafe_context_files_seen_rejected",
    )
    if files_reason:
        return _contextual_failure_signal(
            files_reason,
            engine=stable_engine,
            file_path=file_path,
            tag_evidence=tag_evidence,
        )
    persisted_state, state_reason = _mapping_get_status(
        baseline,
        "tag_evidence",
        None,
    )
    if state_reason or no_hook_mapping_items(persisted_state) is None:
        return _contextual_failure_signal(
            state_reason or "persisted_tag_evidence_records_rejected",
            engine=stable_engine,
            file_path=file_path,
            files_seen=files,
            tag_evidence=tag_evidence,
        )
    root_records = _contextual_root_records(tag_evidence)
    anchors = _contextual_anchor_tags(root_records)
    failure_count = tag_evidence.summary.get("failure_count", 0)
    if (
        failure_count
        or TAG_NORMALIZATION_FAILURE_EVIDENCE in tag_evidence.tags
        or DETECTION_STAGE_DEGRADED_TAG in tag_evidence.tags
    ):
        return _contextual_expected_degraded_signal(
            engine=stable_engine,
            file_path=file_path,
            files=files,
            anchors=anchors,
            tag_evidence=tag_evidence,
        )
    return _contextual_expected_reduction_signal(
        engine=stable_engine,
        file_path=file_path,
        persisted_tag_evidence=persisted_state,
        tag_evidence=tag_evidence,
        root_records=root_records,
        files=files,
        anchors=anchors,
    )


def contextual_expected_behavior_signal(
    engine: ContextualValue,
    file_path: ContextualValue,
    tags: ContextualValue,
    strings_blob: ContextualValue = "",
    api_calls: ContextualValue | None = None,
    ordered_events: ContextualValue | None = None,
    routing_evidence_context: object | None = None,
    router_identity: object | None = None,
) -> ContextualMapping:
    """Return contextual score-reduction evidence from canonical tag records."""
    del strings_blob, api_calls, ordered_events
    tag_evidence = _canonical_contextual_evidence(tags)
    try:
        return _contextual_signal_from_evidence(
            engine=engine,
            file_path=file_path,
            tag_evidence=tag_evidence,
            routing_evidence_context=routing_evidence_context,
            router_identity=router_identity,
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        stable_engine = canonical_profile_name(engine)
        if stable_engine not in DETECTION_PROFILE_NAMES:
            stable_engine = "other"
        failure = recoverable_failure_evidence(
            stage_name="contextual_expected_behavior_signal",
            error_source="contextual_expected_behavior_signal",
            error=error,
            affected_context=_contextual_text(file_path, "<unreadable_path>"),
        )
        payload = failure_evidence_payload((failure,))
        return {
            "version": CONTEXTUAL_BASELINE_VERSION,
            "applied": False,
            "reason": "contextual_signal_error",
            "error": _contextual_text(error, no_hook_type_name(error)),
            "engine": stable_engine,
            "extension": normalize_profile_extension(file_path),
            "distinct_root_count": 0,
            "tag_evidence_summary": dict(tag_evidence.summary),
            "tag_evidence_kinds_consumed": tuple(sorted(_CONTEXTUAL_EVIDENCE_KINDS)),
            "reduction": 0.0,
            "failure_evidence": payload["failures"],
            "scanner_degraded": payload["degraded"],
            "confidence_degraded": payload["confidence_degraded"],
        }


def apply_contextual_expected_behavior_score_from_request(
    request: ContextualExpectedScoreRequest,
) -> ContextualScoreSignal:
    """Apply contextual scoring through the sole immutable request contract."""
    if type(request) is not ContextualExpectedScoreRequest:
        signal = _contextual_failure_signal(
            "contextual_score_request_rejected",
            engine="other",
            file_path="<unreadable_path>",
        )
        return 0.0, signal
    if type(request.tag_evidence) is not TagEvidence:
        old_score = _contextual_score(request.score)
        signal = _contextual_failure_signal(
            "contextual_tag_evidence_required",
            engine=canonical_profile_name(request.engine),
            file_path=request.file_path,
        )
        signal["old_score"] = old_score
        signal["new_score"] = old_score
        return old_score, signal
    signal = contextual_expected_behavior_signal(
        request.engine,
        request.file_path,
        request.tag_evidence,
        routing_evidence_context=request.routing_evidence_context,
        router_identity=request.router_identity,
    )
    old_score = _contextual_float(request.score)
    if not dict.get(signal, "applied"):
        signal["old_score"] = old_score
        signal["new_score"] = old_score
        return old_score, signal
    reduction = _contextual_float(dict.get(signal, "reduction", 0.0))
    min_keep = (
        CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR
        if dict.get(signal, "anchors")
        else CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR
    )
    new_score = max(min_keep, old_score - reduction)
    if old_score >= 75.0:
        new_score = max(new_score, old_score - min(10.0, reduction))
    signal["old_score"] = old_score
    signal["new_score"] = new_score
    signal["score_floor"] = min_keep
    return _contextual_score(new_score), signal


__all__ = (
    "ContextualExpectedScoreRequest",
    "apply_contextual_expected_behavior_score_from_request",
    "contextual_expected_behavior_signal",
)
