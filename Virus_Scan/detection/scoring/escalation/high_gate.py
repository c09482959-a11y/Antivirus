"""High-score authority gate over canonical chain evidence."""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.scoring.escalation.anchor_constants import (
    HIGH_GATE_MAX_WITHOUT_AUTHORITY,
    HIGH_GATE_SINGLE_ANCHOR_TAGS,
    HIGH_GATE_VERSION,
    HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS,
)
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    norm_lower_set,
    normalize_tags,
)


_HIGH_THRESHOLD = 50.0


def _normal_tags(value: object) -> set[str]:
    normalized = norm_lower_set(normalize_tags(() if value is None else value))
    archive_inner = {
        tag.split(":", 1)[1]
        for tag in normalized
        if tag.startswith("archive_inner:") and ":" in tag
    }
    return normalized | archive_inner


def _authoritative_chain_records(evidence: object) -> tuple[dict[str, object], ...]:
    if not hasattr(evidence, "decisions"):
        return ()
    records: list[dict[str, object]] = []
    for decision in evidence.decisions:
        if (
            decision.status == "confirmed"
            and decision.scoreable
            and decision.candidate.order_class in {"observed_order", "causal_link"}
        ):
            records.append(decision.to_record())
    return tuple(records[:40])


def high_gate_authority(
    chain_evidence: ChainEvidence,
    *,
    tags: object | None = None,
    path: object | None = None,
) -> dict[str, object]:
    """Decide HIGH authority from the exact canonical chain bundle."""
    del path
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError('canonical_chain_evidence_required')
    norm = _normal_tags(tags)
    single = tuple(sorted(norm & HIGH_GATE_SINGLE_ANCHOR_TAGS))[:40]
    evidence = chain_evidence
    chain_records = _authoritative_chain_records(evidence)
    chain_ids = tuple(record["chain_id"] for record in chain_records)
    candidate_records = tuple(
        decision.to_record()
        for decision in evidence.decisions
        if decision.status in {"candidate", "partial"}
    )[:40]
    allowed = bool(single or chain_records)
    return {
        "version": HIGH_GATE_VERSION,
        "allowed_high": allowed,
        "single_anchors": single,
        "explicit_behavior_anchors": chain_ids,
        "attack_chains": chain_ids,
        "chain_records": chain_records,
        "candidate_chain_records": candidate_records,
        "chain_registry_version": evidence.registry_version,
        "chain_registry_digest": evidence.registry_digest,
        "chain_failures": tuple(dict(item) for item in evidence.failures),
        "strong_partial_chains": (),
        "strong_partial_chain_anchor_present": False,
        "strong_partial_chain_meta": {"allowed_high": False, "chains": (), "floor": 0.0},
        "degraded": bool(
            evidence.failures
            or TAG_NORMALIZATION_FAILURE_EVIDENCE in norm
            or DETECTION_STAGE_DEGRADED_TAG in norm
        ),
        "weak_or_structural_hits": tuple(sorted(norm & HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS))[:50],
        "maximum_chain_anchor_floor": evidence.maximum_anchor_floor,
    }


def apply_anchor_chain_high_gate(
    score: object,
    chain_evidence: ChainEvidence,
    *,
    tags: object | None = None,
    path: object | None = None,
) -> tuple[float, dict[str, object]]:
    old, score_reason = no_hook_finite_float(
        score,
        default=0.0,
        reason="anchor_chain_high_gate_score_rejected",
        non_finite_reason="anchor_chain_high_gate_score_rejected",
    )
    info = high_gate_authority(
        chain_evidence,
        tags=tags,
        path=path,
    )
    info["old_score"] = old
    info["cap_applied"] = False
    info["new_score"] = old
    if score_reason:
        info["score_materialization_failure"] = score_reason
        info["degraded"] = True
    if old >= _HIGH_THRESHOLD and not info["allowed_high"]:
        capped = min(old, HIGH_GATE_MAX_WITHOUT_AUTHORITY)
        info["cap_applied"] = True
        info["reason"] = "high_requires_concrete_single_anchor_or_confirmed_chain"
        info["new_score"] = capped
        return capped, info
    floor, floor_reason = no_hook_finite_float(
        info.get("maximum_chain_anchor_floor"),
        default=0.0,
        reason="anchor_chain_floor_rejected",
        non_finite_reason="anchor_chain_floor_rejected",
    )
    if floor_reason:
        info["chain_anchor_floor_failure"] = floor_reason
        info["degraded"] = True
    if floor > old and info["allowed_high"]:
        info["chain_anchor_floor_applied"] = True
        info["reason"] = "canonical_chain_anchor_floor"
        info["new_score"] = floor
        return floor, info
    info["chain_anchor_floor_applied"] = False
    return old, info


__all__ = ("apply_anchor_chain_high_gate", "high_gate_authority")
