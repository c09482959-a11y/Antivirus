"""Canonical attack-phase projection from immutable tag evidence.

This module deliberately publishes phase-level evidence only. It does not claim
MITRE technique IDs or verified ATT&CK dataset coverage without the external
validated MITRE resource contract.
"""
from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.tag_evidence import active_tag_evidence_records
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.registries.chain_registry import CHAIN_FAMILY_ATTACK_PHASES

ATTACK_PHASE_PROJECTION_VERSION = "tag_evidence_attack_phase_v2"
_ATTACK_PHASE_EVIDENCE_KINDS = frozenset({
    "observed", "normalized", "derived", "composite",
})


def attack_phase_evidence(
    tags: object,
    chain_evidence: ChainEvidence,
    *,
    allowed_evidence_kinds: frozenset[str] = _ATTACK_PHASE_EVIDENCE_KINDS,
) -> dict[str, object]:
    """Project ATT&CK phases with one signal count per independent evidence root."""
    if type(chain_evidence) is not ChainEvidence:
        return {
            "version": ATTACK_PHASE_PROJECTION_VERSION,
            "ready": False,
            "mapping_scope": "attack_phase_only",
            "technique_ids_claimed": False,
            "phase_hits": {},
            "unavailable_reason": "attack_phase_chain_evidence_required",
        }
    if (
        type(allowed_evidence_kinds) is not frozenset
        or not allowed_evidence_kinds
        or not allowed_evidence_kinds <= _ATTACK_PHASE_EVIDENCE_KINDS
    ):
        return {
            "version": ATTACK_PHASE_PROJECTION_VERSION,
            "ready": False,
            "mapping_scope": "attack_phase_only",
            "technique_ids_claimed": False,
            "phase_hits": {},
            "unavailable_reason": "attack_phase_evidence_kind_declaration_rejected",
        }
    bundle = scoreable_tag_evidence(
        tags,
        allowed_evidence_kinds=allowed_evidence_kinds,
    )
    active = tuple(
        record for record in active_tag_evidence_records(bundle.records)
        if record.evidence_kind in allowed_evidence_kinds
        and record.polarity == "positive"
    )
    roots_by_phase: dict[str, set[str]] = {}
    for record in active:
        phase = record.attack_phase
        if phase and phase != "unknown":
            roots_by_phase.setdefault(phase, set()).add(record.root_observation_id)

    primary_canonicals_by_root: dict[str, set[str]] = {}
    for record in active:
        if record.evidence_kind in {"observed", "normalized"}:
            primary_canonicals_by_root.setdefault(
                record.root_observation_id, set(),
            ).add(record.canonical_tag_id)

    phase_hits: dict[str, object] = {}
    for phase in sorted(roots_by_phase):
        roots = roots_by_phase[phase]
        phase_records = tuple(
            record for record in active
            if record.attack_phase == phase and record.root_observation_id in roots
        )
        publication_records = tuple(
            record for record in phase_records
            if (
                record.evidence_kind in {"observed", "normalized"}
                or record.canonical_tag_id in primary_canonicals_by_root.get(
                    record.root_observation_id, set(),
                )
            )
        )
        matched = tuple(sorted({
            record.publication_name for record in publication_records
            if record.publication_name
        }))
        correlation_groups = tuple(sorted({
            record.correlation_group for record in phase_records
            if record.correlation_group
        }))
        phase_hits[phase] = {
            "matched": matched,
            "distinct_root_count": len(roots),
            "distinct_correlation_group_count": len(correlation_groups),
            "root_observation_ids": tuple(sorted(roots)),
            "correlation_groups": correlation_groups,
            "evidence": tuple(record.to_record() for record in phase_records[:64]),
        }

    chain_states_by_phase: dict[str, dict[str, list[dict[str, object]]]] = {}
    for decision in chain_evidence.decisions:
        if decision.status not in {"confirmed", "candidate", "partial", "blocked"}:
            continue
        phases = CHAIN_FAMILY_ATTACK_PHASES.get(decision.candidate.family, ())
        for phase in phases:
            state = chain_states_by_phase.setdefault(
                phase,
                {"confirmed": [], "candidate": [], "partial": [], "blocked": []},
            )
            state[decision.status].append(decision.to_record())
    for phase, states in sorted(chain_states_by_phase.items()):
        phase_record = phase_hits.setdefault(phase, {
            "matched": (),
            "distinct_root_count": 0,
            "distinct_correlation_group_count": 0,
            "root_observation_ids": (),
            "correlation_groups": (),
            "evidence": (),
        })
        phase_record["chain_states"] = {
            status: tuple(records[:32])
            for status, records in states.items()
            if records
        }

    reason = str(bundle.reasons.get("unavailable_reason", ""))
    result = {
        "version": ATTACK_PHASE_PROJECTION_VERSION,
        "ready": bool(phase_hits) and not reason,
        "mapping_scope": "attack_phase_only",
        "technique_ids_claimed": False,
        "phase_hits": phase_hits,
        "tag_evidence_summary": dict(bundle.summary),
        "tag_evidence_kinds_consumed": tuple(sorted(allowed_evidence_kinds)),
        "chain_registry_version": chain_evidence.registry_version,
        "chain_registry_digest": chain_evidence.registry_digest,
        "chain_state_scoring": "publication_only_no_duplicate_phase_score",
    }
    if reason:
        result["unavailable_reason"] = reason
    elif not phase_hits:
        result["unavailable_reason"] = "attack_phase_evidence_absent"
    return result


__all__ = (
        "ATTACK_PHASE_PROJECTION_VERSION",
        "attack_phase_evidence",
)
