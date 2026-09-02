"""Bounded ATT&CK phase scoring over canonical tag evidence roots."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.detection.tags.heuristics.attack_phase_projection import attack_phase_evidence

_PHASE_WEIGHTS = MappingProxyType({
    "execution": 8.0,
    "persistence": 9.0,
    "credential_access": 12.0,
    "defense_evasion": 12.0,
    "collection": 8.0,
    "exfiltration": 13.0,
    "lateral_movement": 14.0,
    "privilege_escalation": 9.0,
})
_ATTACK_PHASE_EVIDENCE_KINDS = frozenset({
    "observed", "normalized", "derived", "composite",
})


def attack_phase_probability(value: object) -> object:
    return safe_clamp(value, 0.0, 1.0)


def classify_attack_graph_phases(tags: object, chain_evidence: ChainEvidence) -> dict[str, object]:
    """Score phase coverage from distinct roots, never matched alias count."""
    phase_evidence = attack_phase_evidence(
        tags,
        chain_evidence,
        allowed_evidence_kinds=_ATTACK_PHASE_EVIDENCE_KINDS,
    )
    source_hits = phase_evidence.get("phase_hits", {})
    if type(source_hits) is not dict or not source_hits:
        return {"phase_score": 0.0, "raw_phase_score": 0.0, "phase_hits": {}}

    phase_hits: dict[str, object] = {}
    total_score = 0.0
    for phase, phase_weight in _PHASE_WEIGHTS.items():
        evidence = source_hits.get(phase)
        if type(evidence) is not dict:
            continue
        matched = list(evidence.get("matched", ()))
        root_count = evidence.get("distinct_root_count", 0)
        if type(root_count) is not int or type(root_count) is bool or root_count <= 0:
            continue
        ratio = min(1.0, root_count / 2.0)
        score = phase_weight * ratio
        phase_hits[phase] = {
            "matched": matched,
            "ratio": ratio,
            "score": score,
            "distinct_root_count": root_count,
            "distinct_correlation_group_count": evidence.get(
                "distinct_correlation_group_count", 0,
            ),
            "chain_states": evidence.get("chain_states", {}),
        }
        total_score += score
    if not phase_hits:
        return {"phase_score": 0.0, "raw_phase_score": 0.0, "phase_hits": {}}
    return {
        "phase_score": attack_phase_probability(total_score / 45.0),
        "raw_phase_score": total_score,
        "phase_hits": phase_hits,
        "tag_evidence_summary": phase_evidence.get("tag_evidence_summary", {}),
        "tag_evidence_kinds_consumed": tuple(sorted(_ATTACK_PHASE_EVIDENCE_KINDS)),
        "mapping_scope": phase_evidence.get("mapping_scope", "attack_phase_only"),
        "technique_ids_claimed": False,
    }
